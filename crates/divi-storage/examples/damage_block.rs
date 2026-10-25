//! Test tool for scripts/start-checks: damage one block's stored data in a
//! COPY of an irondivid chain database, as a damaged block or undo file
//! would be in Divi Core's blocks/ folder. Run it only on a stopped node's
//! datadir made for a test.
//!
//! usage:
//!   damage_block <chainstate-dir> <height> block-bad      (a transaction changed: the merkle root no longer matches)
//!   damage_block <chainstate-dir> <height> block-missing  (the block's data removed)
//!   damage_block <chainstate-dir> <height> undo-bad       (undo data that does not decode)
//!   damage_block <chainstate-dir> <height> hash           (print the block hash only)
use divi_storage::ChainDatabase;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: damage_block <chainstate-dir> <height> block-bad|block-missing|undo-bad|hash"
        );
        std::process::exit(2);
    }
    let (path, what) = (&args[1], args[3].as_str());
    let height: u32 = args[2].parse().expect("height");
    let hash = {
        let db = ChainDatabase::open(path).expect("open the chain database");
        let hash = db
            .get_height_mapping(height)
            .expect("read the height index")
            .expect("no block at that height");
        match what {
            "hash" => {}
            "block-bad" => {
                let mut block = db.get_block(&hash).expect("read").expect("no block data");
                let tx = block.transactions.last_mut().expect("a transaction");
                tx.lock_time ^= 1;
                db.store_block(&hash, &block).expect("write the block");
            }
            "undo-bad" => db
                .store_undo_data(&hash, &[0xff; 7])
                .expect("write the undo data"),
            "block-missing" => {}
            _ => {
                eprintln!("unknown damage {what}");
                std::process::exit(2);
            }
        }
        hash
    };
    if what == "block-missing" {
        // ChainDatabase has no way to drop a block; remove its key directly
        let opts = rocksdb::Options::default();
        let cfs = rocksdb::DB::list_cf(&opts, path).expect("list the column families");
        let db = rocksdb::DB::open_cf(&opts, path, &cfs).expect("open the column families");
        let cf = db.cf_handle("blocks").expect("a blocks column family");
        db.delete_cf(cf, hash.as_bytes()).expect("delete the block");
    }
    println!("{hash}");
}
