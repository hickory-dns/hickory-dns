#[derive(Debug)]
pub struct RRSet {
  origin: Name,
  // TODO create a RRSet that is HashSet, but also embeds the RRSig record.
  records: HashSet<Record>,
  zone_type: ZoneType,
  allow_update: bool,
}
