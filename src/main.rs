use std::collections::{HashSet, HashMap};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::rc::{Rc, Weak};
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::fmt;



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relationships {
    // DO NOT CHANGE THE ORDER!
    // This order matters for Gao rexford funcs
    PROVIDERS = 1,
    PEERS = 2,
    // Customers have the highest priority for economic incentives
    CUSTOMERS = 3,
    // Origin always has announcements, never overwrite them
    ORIGIN = 4,
    // Useful for other programs
    UNKNOWN = 5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Announcement {
    prefix: String,
    as_path: Vec<u32>,
    timestamp: i64,
    seed_asn: Option<u32>,
    roa_valid_length: Option<bool>,
    roa_origin: Option<u32>,
    recv_relationship: Relationships,
    withdraw: bool,
    traceback_end: bool,
    communities: Vec<String>,
}

impl Announcement {
    fn prefix_path_attributes_eq(&self, other: &Option<Announcement>) -> bool {
        match other {
            Some(ann) => ann.prefix == self.prefix && ann.as_path == self.as_path,
            None => false,
        }
    }

    fn invalid_by_roa(&self) -> bool {
        if let Some(roa_origin) = self.roa_origin {
            self.origin() != roa_origin || !self.roa_valid_length.unwrap_or(false)
        } else {
            false
        }
    }

    fn valid_by_roa(&self) -> bool {
        if let Some(roa_origin) = self.roa_origin {
            self.origin() == roa_origin && self.roa_valid_length.unwrap_or(false)
        } else {
            false
        }
    }

    fn unknown_by_roa(&self) -> bool {
        !self.invalid_by_roa() && !self.valid_by_roa()
    }

    fn covered_by_roa(&self) -> bool {
        !self.unknown_by_roa()
    }

    fn roa_routed(&self) -> bool {
        self.roa_origin.unwrap_or(0) != 0
    }

    fn origin(&self) -> u32 {
        *self.as_path.last().unwrap()
    }
}
// Helper functions to parse specific types
fn parse_as_path(input: &str) -> Vec<u32> {
    input.split(',').filter_map(|s| s.trim().parse().ok()).collect()
}

fn parse_relationship(input: &str) -> Relationships {
    match input {
        "PROVIDERS" => Relationships::PROVIDERS,
        "PEERS" => Relationships::PEERS,
        "CUSTOMERS" => Relationships::CUSTOMERS,
        "ORIGIN" => Relationships::ORIGIN,
        _ => Relationships::UNKNOWN,
    }
}

fn parse_communities(input: &str) -> Vec<String> {
    input.split(',').map(|s| s.trim().to_string()).collect()
}

impl Hash for Announcement {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Create a string representation of the fields that should contribute to the hash
        let composite_key = format!("{}{:?}{}", self.prefix, self.as_path, self.recv_relationship as u32);

        // Hash this composite key
        composite_key.hash(state);
    }
}

// Additionally, implement fmt::Display for a user-friendly string representation
impl fmt::Display for Announcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:?} {:?}", self.prefix, self.as_path, self.recv_relationship)
    }
}

// LocalRIB structure
#[derive(Debug)]
struct LocalRIB {
    info: RefCell<HashMap<String, Announcement>>,
}

impl LocalRIB {
    fn new() -> LocalRIB {
        LocalRIB {
            info: RefCell::new(HashMap::new()),
        }
    }

    fn get_ann(&self, prefix: &str) -> Option<Announcement> {
        self.info.borrow().get(prefix).cloned()
    }

    fn add_ann(&self, ann: Announcement) {
        self.info.borrow_mut().insert(ann.prefix.clone(), ann);
    }

    fn remove_ann(&self, prefix: &str) {
        self.info.borrow_mut().remove(prefix);
    }

    fn prefix_anns(&self) -> HashMap<String, Announcement> {
        self.info.borrow().clone()
    }
}

// RecvQueue structure
#[derive(Debug)]
struct RecvQueue {
    info: RefCell<HashMap<String, Vec<Announcement>>>,
}

impl RecvQueue {
    fn new() -> RecvQueue {
        RecvQueue {
            info: RefCell::new(HashMap::new()),
        }
    }

    fn add_ann(&self, ann: Announcement) {
        let mut info = self.info.borrow_mut();
        info.entry(ann.prefix.clone()).or_insert_with(Vec::new).push(ann);
    }

    fn prefix_anns(&self) -> HashMap<String, Vec<Announcement>> {
        self.info.borrow().clone()
    }

    fn get_ann_list(&self, prefix: &str) -> Vec<Announcement> {
        self.info.borrow().get(prefix).cloned().unwrap_or_else(Vec::new)
    }
}

// BGPSimplePolicy structure
#[derive(Debug)]
struct BGPSimplePolicy {
    as_ref: Weak<AS>,
    local_rib: LocalRIB,
    recv_queue: RecvQueue,
    gao_rexford_funcs: Vec<Box<dyn Fn(&Announcement, bool, Relationships, &Announcement, bool, Relationships) -> GaoRexfordPref>>,
}

impl BGPSimplePolicy {
    fn new(as_ref: Weak<AS>) -> BGPSimplePolicy {
        BGPSimplePolicy {
            as_ref,
            local_rib: LocalRIB::new(),
            recv_queue: RecvQueue::new(),
        }
    }

    // Additional methods...
    fn receive_ann(&mut self, ann: &Announcement) {
        self.recv_queue.add_ann(ann.clone());
    }
    fn valid_ann(&self, ann: &Announcement) -> bool {
        // BGP Loop Prevention Check
        let as_ref = self.as_ref.upgrade().expect("AS object is dropped");
        !ann.as_path.contains(&as_ref.asn)
    }

    fn reset_q(&mut self, reset_q: bool) {
        if reset_q {
            self.recv_queue = RecvQueue::new();
        }
    }

    fn copy_and_process(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
    ) -> Announcement {
        let mut new_ann = ann.clone();

        // Prepend AS to AS Path and set recv_relationship
        if let Some(as_ref) = self.as_ref.upgrade() {
            new_ann.as_path.insert(0, as_ref.asn);
        }
        new_ann.recv_relationship = recv_relationship;
        new_ann
    }


    fn process_incoming_anns(&mut self, from_rel: Relationships, propagation_round: i32, reset_q: bool) {
        for (prefix, ann_list) in self.recv_queue.prefix_anns() {
            let mut current_ann = self.local_rib.get_ann(&prefix).cloned();
            let mut current_processed = current_ann.is_some();

            if current_ann.as_ref().map_or(false, |ann| ann.seed_asn.is_some()) {
                continue;
            }

            for ann in ann_list {
                if self.valid_ann(ann) {
                    let new_ann_better = self._new_ann_better(
                        current_ann.as_ref(),
                        current_processed,
                        from_rel,
                        ann,
                        false,
                        from_rel,
                    );

                    if new_ann_better {
                        current_ann = Some(ann.clone());
                        current_processed = false;
                    }
                }
            }

            if !current_processed {
                if let Some(ann) = current_ann {
                    let processed_ann = self.copy_and_process(&ann, from_rel);
                    self.local_rib.add_ann(processed_ann);
                }
            }
        }

        if reset_q {
            self.reset_q(reset_q);
        }
    }
}

// Define the AS structure
#[derive(Debug)]
struct AS {
    asn: u32,
    customers: RefCell<Vec<Weak<AS>>>,
    providers: RefCell<Vec<Weak<AS>>>,
    peers: RefCell<Vec<Weak<AS>>>,
    propagation_rank: RefCell<Option<u32>>,
    policy: RefCell<BGPSimplePolicy>,
}

// Define the ASGraph structure
struct ASGraph {
    ases: HashMap<u32, Rc<AS>>,
}

impl ASGraph {
    fn new() -> ASGraph {
        ASGraph {
            ases: HashMap::new(),
        }
    }

    fn add_as(&mut self, asn: u32) -> Rc<AS> {
        let new_as = Rc::new(AS {
            asn,
            customers: RefCell::new(Vec::new()),
            providers: RefCell::new(Vec::new()),
            peers: RefCell::new(Vec::new()),
            propagation_rank: RefCell::new(None),
            policy: RefCell::new(BGPSimplePolicy::new(Weak::new())), // Temporary weak reference
        });

        // Update the policy with the correct weak reference to the AS
        let weak_as_ref = Rc::downgrade(&new_as);
        *new_as.policy.borrow_mut() = BGPSimplePolicy::new(weak_as_ref);

        self.ases.insert(asn, new_as.clone());
        new_as
    }

    fn connect_as(&mut self, asn1: u32, asn2: u32, relation_type: &str) {
        let as1 = self.ases.get(&asn1).unwrap().clone();
        let as2 = self.ases.get(&asn2).unwrap().clone();

        match relation_type {
            "peer" => {
                as1.peers.borrow_mut().push(Rc::downgrade(&as2));
                as2.peers.borrow_mut().push(Rc::downgrade(&as1));
            }
            "customer" => {
                as1.customers.borrow_mut().push(Rc::downgrade(&as2));
                as2.providers.borrow_mut().push(Rc::downgrade(&as1));
            }
            "provider" => {
                as1.providers.borrow_mut().push(Rc::downgrade(&as2));
                as2.customers.borrow_mut().push(Rc::downgrade(&as1));
            }
            _ => {}
        }
    }

    fn calculate_propagation_ranks(&mut self) {
        for as_obj in self.ases.values() {
            self._assign_ranks_helper(as_obj, 0);
        }
    }

    fn _assign_ranks_helper(&self, as_obj: &Rc<AS>, rank: u32) {
        let mut as_obj_rank = as_obj.propagation_rank.borrow_mut();
        if as_obj_rank.is_none() || as_obj_rank.unwrap() < rank {
            *as_obj_rank = Some(rank);
            for provider_weak in as_obj.providers.borrow().iter() {
                if let Some(provider) = provider_weak.upgrade() {
                    self._assign_ranks_helper(&provider, rank + 1);
                }
            }
        }
    }
}



// ... [rest of your code, including struct definitions and helper functions]

fn main() -> io::Result<()> {
    let path = "/tmp/caida_collector.tsv";
    let mut as_graph = ASGraph::new();
    let mut unique_asns = HashSet::new();

    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    // First loop: Collect all unique ASNs
    for line in reader.lines() {
        let line = line?;
        if line.starts_with("asn") {
            continue; // Skip header line
        }

        let columns: Vec<&str> = line.split('\t').collect();
        let asn = columns[0].parse::<u32>().unwrap();
        unique_asns.insert(asn);
    }

    // Add all ASes to the graph
    for asn in unique_asns {
        as_graph.add_as(asn);
    }

    // Re-open the file for the second pass
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    // Second loop: Establish connections
    for line in reader.lines() {
        let line = line?;
        if line.starts_with("asn") {
            continue; // Skip header line
        }

        let columns: Vec<&str> = line.split('\t').collect();
        let asn = columns[0].parse::<u32>().unwrap();
        let peers = parse_asn_list(columns[1]);
        let customers = parse_asn_list(columns[2]);
        let providers = parse_asn_list(columns[3]);

        for peer in peers {
            as_graph.connect_as(asn, peer, "peer");
        }
        for customer in customers {
            as_graph.connect_as(asn, customer, "customer");
        }
        for provider in providers {
            as_graph.connect_as(asn, provider, "provider");
        }
    }

    as_graph.calculate_propagation_ranks();

    // Printing ranks for verification
    for (asn, as_obj) in as_graph.ases.iter() {
        let rank = as_obj.propagation_rank.borrow()
            .expect("Rank should be assigned");
        println!("ASN: {}, Rank: {}", asn, rank);
    }

    Ok(())
}
// Helper function to parse ASN lists from the TSV
fn parse_asn_list(asn_list_str: &str) -> Vec<u32> {
    asn_list_str.trim_matches('{').trim_matches('}')
        .split(',')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect()
}
