//! OpenCL search for the optional GPU mining backend.

use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use ocl::{Buffer, Context, Device, DeviceType, Kernel, MemFlags, Platform, Program, Queue};
use proof_core::{Address, ChallengeInputs, Digest, Target, Uint256, derive_challenge, meets_target, proof_digest, ProofInputs, proof_preimage};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub index: usize,
    pub name: String,
}

pub fn devices() -> std::result::Result<Vec<DeviceInfo>, String> {
    let mut found = Vec::new();
    for platform in Platform::list() {
        let devices = Device::list(platform, Some(DeviceType::GPU))
            .map_err(|error| format!("failed to enumerate OpenCL devices: {error}"))?;
        for device in devices {
            let name = device
                .name()
                .map_err(|error| format!("failed to read OpenCL device name: {error}"))?;
            found.push(DeviceInfo {
                index: found.len(),
                name,
            });
        }
    }
    if found.is_empty() {
        return Err("no OpenCL devices found; install the vendor OpenCL runtime/ICD".to_owned());
    }
    Ok(found)
}

#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub challenge_inputs: ChallengeInputs,
    pub miner: Address,
    pub target: Target,
    pub start_nonce: Uint256,
    pub max_attempts: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Result {
    Found { nonce: Uint256, digest: Digest, attempts: u128, devices: usize },
    Exhausted { attempts: u128, devices: usize },
    Abandoned { attempts: u128, devices: usize },
}

const KERNEL: &str = r#"
__constant ulong RC[24]={1UL,0x8082UL,0x800000000000808aUL,0x8000000080008000UL,0x808bUL,0x80000001UL,0x8000000080008081UL,0x8000000000008009UL,0x8aUL,0x88UL,0x80008009UL,0x8000000aUL,0x8000808bUL,0x800000000000008bUL,0x8000000000008089UL,0x8000000000008003UL,0x8000000000008002UL,0x8000000000000080UL,0x800aUL,0x800000008000000aUL,0x8000000080008081UL,0x8000000000008080UL,0x80000001UL,0x8000000080008008UL};
__constant int PI[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
__constant int RH[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
ulong rol(ulong x,int n){return n?((x<<n)|(x>>(64-n))):x;}
void perm(ulong a[25]){for(int r=0;r<24;r++){ulong c[5],d[5];for(int x=0;x<5;x++)c[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];for(int x=0;x<5;x++)d[x]=c[(x+4)%5]^rol(c[(x+1)%5],1);for(int i=0;i<25;i++)a[i]^=d[i%5];ulong t=a[1],u;for(int i=0;i<24;i++){u=a[PI[i]];a[PI[i]]=rol(t,RH[i]);t=u;}for(int y=0;y<5;y++){ulong b0=a[5*y],b1=a[1+5*y],b2=a[2+5*y],b3=a[3+5*y],b4=a[4+5*y];a[5*y]=b0^((~b1)&b2);a[1+5*y]=b1^((~b2)&b3);a[2+5*y]=b2^((~b3)&b4);a[3+5*y]=b3^((~b4)&b0);a[4+5*y]=b4^((~b0)&b1);}a[0]^=RC[r];}}
ulong rev(ulong x){return ((x&0xffUL)<<56)|((x&0xff00UL)<<40)|((x&0xff0000UL)<<24)|((x&0xff000000UL)<<8)|((x>>8)&0xff000000UL)|((x>>24)&0xff0000UL)|((x>>40)&0xff00UL)|((x>>56)&0xffUL);}
void add_offset(__private ulong n[4],__private ulong off){for(int i=3;i>=0;i--){ulong old=n[i];n[i]+=off;off=(n[i]<old)?1UL:0UL;if(!off)break;}}
__kernel void mine(__global const uchar* prefix,__global const uchar* target,__global const ulong* base,ulong offset,ulong valid,uint iters,volatile __global uint* found,__global ulong* out_nonce,__global uchar* out_hash,volatile __global uint* bestbits){
 ulong gid=get_global_id(0); ulong stride=get_global_size(0); ulong n_off=offset+gid*iters;
 for(uint it=0;it<iters;it++){if(gid*iters+(ulong)it>=valid||found[0])return; ulong n[4]={base[0],base[1],base[2],base[3]};add_offset(n,n_off+(ulong)it); ulong a[25];for(int i=0;i<25;i++)a[i]=0;
  for(int i=0;i<17;i++){ulong v=0;for(int k=0;k<8;k++)v|=((ulong)prefix[i*8+k])<<(8*k);a[i]^=v;}perm(a);
  for(int i=0;i<11;i++){ulong v=0;for(int k=0;k<8;k++)v|=((ulong)prefix[136+i*8+k])<<(8*k);a[i]^=v;}
  a[11]^=rev(n[0]);a[12]^=rev(n[1]);a[13]^=rev(n[2]);a[14]^=rev(n[3]);a[15]^=1UL;a[16]^=0x8000000000000000UL;perm(a);
  uchar h[32];for(int i=0;i<4;i++)for(int k=0;k<8;k++)h[i*8+k]=(uchar)(a[i]>>(8*k));uint bits=0;for(int i=0;i<32;i++){if(h[i]==0)bits+=8;else{uint v=(uint)h[i];while((v&0x80U)==0){bits++;v<<=1;}break;}}atomic_max(bestbits,bits);int accepted=1;for(int i=0;i<32;i++){if(h[i]<target[i])break;if(h[i]>target[i]){accepted=0;break;}}if(accepted&&atomic_cmpxchg(found,0,1)==0){for(int i=0;i<4;i++)out_nonce[i]=n[i];for(int i=0;i<32;i++)out_hash[i]=h[i];}}
}
"#;

pub fn mine(request: Request, stop: Arc<AtomicBool>) -> std::result::Result<Result, String> {
    let all = opencl_devices()?;
    let count = all.len();
    let cursor = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let bestbits = Arc::new(AtomicU64::new(0));
    let reporter_done = Arc::new(AtomicBool::new(false));
    let reporter = {
        let attempts = Arc::clone(&attempts);
        let bestbits = Arc::clone(&bestbits);
        let done = Arc::clone(&reporter_done);
        let target = request.target;
        let devices = count;
        thread::spawn(move || report_progress(attempts, bestbits, done, target, devices))
    };
    let mut handles = Vec::new();
    for (index, device) in all.into_iter().enumerate() {
        let cursor = Arc::clone(&cursor); let found = Arc::clone(&found); let stop = Arc::clone(&stop); let attempts = Arc::clone(&attempts);
        let bestbits = Arc::clone(&bestbits);
        handles.push(thread::spawn(move || device_loop(index, device, request, cursor, found, stop, attempts, bestbits)));
    }
    let mut candidate = None; let mut error = None;
    for handle in handles { match handle.join().map_err(|_| "OpenCL worker panicked".to_owned())? { Ok(Some(value)) => candidate = candidate.or(Some(value)), Ok(None) => {}, Err(value) => error = error.or(Some(value)) } }
    reporter_done.store(true, Ordering::Release);
    let _ = reporter.join();
    let total = u128::from(attempts.load(Ordering::Acquire));
    if let Some(error) = error { return Err(error); }
    if let Some((nonce, digest)) = candidate { return Ok(Result::Found { nonce, digest, attempts: total, devices: count }); }
    if stop.load(Ordering::Acquire) { Ok(Result::Abandoned { attempts: total, devices: count }) } else { Ok(Result::Exhausted { attempts: total, devices: count }) }
}

fn opencl_devices() -> std::result::Result<Vec<Device>, String> {
    let mut result = Vec::new();
    for platform in Platform::list() { result.extend(Device::list(platform, Some(DeviceType::GPU)).map_err(|e| format!("OpenCL device enumeration failed: {e}"))?); }
    if result.is_empty() { Err("no OpenCL devices found; install the vendor OpenCL runtime/ICD".into()) } else { Ok(result) }
}

fn device_loop(index: usize, device: Device, request: Request, cursor: Arc<AtomicU64>, found: Arc<AtomicBool>, stop: Arc<AtomicBool>, attempts: Arc<AtomicU64>, bestbits: Arc<AtomicU64>) -> std::result::Result<Option<(Uint256, Digest)>, String> {
    let context = Context::builder().devices(device).build().map_err(|e| format!("OpenCL device {index} context: {e}"))?;
    let queue = Queue::new(&context, device, None).map_err(|e| format!("OpenCL device {index} queue: {e}"))?;
    let program = Program::builder().devices(device).src(KERNEL).build(&context).map_err(|e| format!("OpenCL device {index} kernel: {e}"))?;
    let preimage = proof_preimage(&ProofInputs { chain_id: request.challenge_inputs.chain_id, mining_core: request.challenge_inputs.mining_core, challenge_id: request.challenge_inputs.challenge_id, challenge: derive_challenge(&request.challenge_inputs), miner: request.miner, nonce: request.start_nonce });
    let base = nonce_words(request.start_nonce);
    let prefix = Buffer::builder().queue(queue.clone()).flags(MemFlags::READ_ONLY | MemFlags::COPY_HOST_PTR).len(224).copy_host_slice(&preimage[..224]).build().map_err(|e| e.to_string())?;
    let target = Buffer::builder().queue(queue.clone()).flags(MemFlags::READ_ONLY | MemFlags::COPY_HOST_PTR).len(32).copy_host_slice(&request.target.to_be_bytes()).build().map_err(|e| e.to_string())?;
    let base_buffer = Buffer::builder().queue(queue.clone()).flags(MemFlags::READ_ONLY | MemFlags::COPY_HOST_PTR).len(4).copy_host_slice(&base).build().map_err(|e| e.to_string())?;
    let found_buffer = Buffer::<u32>::builder().queue(queue.clone()).flags(MemFlags::READ_WRITE).len(1).fill_val(0).build().map_err(|e| e.to_string())?;
    let nonce_buffer = Buffer::<u64>::builder().queue(queue.clone()).flags(MemFlags::READ_WRITE).len(4).fill_val(0).build().map_err(|e| e.to_string())?;
    let hash_buffer = Buffer::<u8>::builder().queue(queue.clone()).flags(MemFlags::READ_WRITE).len(32).fill_val(0).build().map_err(|e| e.to_string())?;
    let best_buffer = Buffer::<u32>::builder().queue(queue.clone()).flags(MemFlags::READ_WRITE).len(1).fill_val(0).build().map_err(|e| e.to_string())?;
    gpu_self_test(index, &queue, &program, &prefix, &base_buffer, &found_buffer, &nonce_buffer, &hash_buffer, &best_buffer, request)?;
    let global = std::env::var("BPROOF_OPENCL_GLOBAL").ok().and_then(|x| x.parse::<usize>().ok()).filter(|x| *x > 0).unwrap_or(1 << 20);
    let iters = std::env::var("BPROOF_OPENCL_ITERS").ok().and_then(|x| x.parse::<u32>().ok()).filter(|x| *x > 0).unwrap_or(16);
    loop {
        if stop.load(Ordering::Acquire) || found.load(Ordering::Acquire) { break; }
        let batch = u64::try_from(global).ok().and_then(|g| g.checked_mul(u64::from(iters))).ok_or("OpenCL batch size overflow")?;
        let (start, valid) = match request.max_attempts { Some(max) => { let old = cursor.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| { if n >= max { None } else { Some(n.saturating_add(batch).min(max)) } }).ok(); old.map(|n| (n, batch.min(max.saturating_sub(n)))) }, None => { let n = cursor.fetch_add(batch, Ordering::AcqRel); Some((n, batch)) } }.unwrap_or((0, 0));
        if valid == 0 { break; }
        let kernel = Kernel::builder().program(&program).name("mine").queue(queue.clone()).global_work_size(global).arg(&prefix).arg(&target).arg(&base_buffer).arg(start).arg(valid).arg(iters).arg(&found_buffer).arg(&nonce_buffer).arg(&hash_buffer).arg(&best_buffer).build().map_err(|e| format!("OpenCL device {index} kernel args: {e}"))?;
        // Kernel arguments and the queue are constructed above; the unsafe call is the only FFI boundary.
        unsafe { kernel.enq().map_err(|e| format!("OpenCL device {index} enqueue: {e}"))?; }
        queue.finish().map_err(|e| format!("OpenCL device {index} finish: {e}"))?;
        attempts.fetch_add(valid, Ordering::AcqRel);
        let mut local_best = vec![0_u32; 1]; best_buffer.read(&mut local_best).enq().map_err(|e| e.to_string())?;
        bestbits.fetch_max(u64::from(local_best[0]), Ordering::AcqRel);
        let mut flag = vec![0_u32; 1]; found_buffer.read(&mut flag).enq().map_err(|e| e.to_string())?;
        if flag[0] != 0 { let mut words=vec![0_u64;4];let mut bytes=vec![0_u8;32];nonce_buffer.read(&mut words).enq().map_err(|e| e.to_string())?;hash_buffer.read(&mut bytes).enq().map_err(|e| e.to_string())?;let nonce=words_to_nonce(words.try_into().unwrap());let digest=Digest::from_bytes(bytes.try_into().unwrap());if meets_target(digest,request.target)&&proof_digest(&ProofInputs{chain_id:request.challenge_inputs.chain_id,mining_core:request.challenge_inputs.mining_core,challenge_id:request.challenge_inputs.challenge_id,challenge:derive_challenge(&request.challenge_inputs),miner:request.miner,nonce})==digest {found.store(true,Ordering::Release);return Ok(Some((nonce,digest)));}return Err(format!("OpenCL device {index} returned a candidate that failed canonical CPU verification")); }
    }
    Ok(None)
}

fn gpu_self_test(index: usize, queue: &Queue, program: &Program, prefix: &Buffer<u8>, base: &Buffer<u64>, found: &Buffer<u32>, nonce: &Buffer<u64>, hash: &Buffer<u8>, best: &Buffer<u32>, request: Request) -> std::result::Result<(), String> {
    let target = Buffer::builder().queue(queue.clone()).flags(MemFlags::READ_ONLY | MemFlags::COPY_HOST_PTR).len(32).copy_host_slice(&[0xff_u8; 32]).build().map_err(|e| format!("OpenCL device {index} self-test target: {e}"))?;
    let zero = vec![0_u32; 1];
    found.write(&zero).enq().map_err(|e| format!("OpenCL device {index} self-test reset: {e}"))?;
    let kernel = Kernel::builder().program(program).name("mine").queue(queue.clone()).global_work_size(1).arg(prefix).arg(&target).arg(base).arg(0_u64).arg(1_u64).arg(1_u32).arg(found).arg(nonce).arg(hash).arg(best).build().map_err(|e| format!("OpenCL device {index} self-test kernel: {e}"))?;
    // The self-test is deliberately one work-item; it validates the kernel's
    // byte order and two-block padding before any result can be submitted.
    unsafe { kernel.enq().map_err(|e| format!("OpenCL device {index} self-test enqueue: {e}"))?; }
    queue.finish().map_err(|e| format!("OpenCL device {index} self-test finish: {e}"))?;
    let mut flag = vec![0_u32; 1]; let mut words = vec![0_u64; 4]; let mut bytes = vec![0_u8; 32];
    found.read(&mut flag).enq().map_err(|e| e.to_string())?; nonce.read(&mut words).enq().map_err(|e| e.to_string())?; hash.read(&mut bytes).enq().map_err(|e| e.to_string())?;
    if flag[0] == 0 { return Err(format!("OpenCL device {index} self-test found no result")); }
    let actual_nonce = words_to_nonce(words.try_into().unwrap()); let actual_digest = Digest::from_bytes(bytes.try_into().unwrap());
    let expected_digest = proof_digest(&ProofInputs { chain_id: request.challenge_inputs.chain_id, mining_core: request.challenge_inputs.mining_core, challenge_id: request.challenge_inputs.challenge_id, challenge: derive_challenge(&request.challenge_inputs), miner: request.miner, nonce: actual_nonce });
    if actual_digest != expected_digest { return Err(format!("OpenCL device {index} self-test failed: kernel digest does not match canonical Keccak")); }
    Ok(())
}

fn report_progress(attempts: Arc<AtomicU64>, bestbits: Arc<AtomicU64>, done: Arc<AtomicBool>, target: Target, devices: usize) {
    let started = Instant::now();
    while !done.load(Ordering::Acquire) {
        thread::sleep(Duration::from_secs(1));
        let total = attempts.load(Ordering::Acquire);
        let elapsed = started.elapsed().as_secs_f64().max(0.001);
        let rate = total as f64 / elapsed;
        let expected = expected_seconds(target, rate);
        let chance = chance_per_minute(target, rate);
        println!("OpenCL mining | GPUs={devices} speed={} hashes={} best={}/256 expected={} chance/min={:.2}%", format_rate(rate), total, bestbits.load(Ordering::Acquire), format_duration(expected), chance * 100.0);
    }
}

fn format_rate(rate: f64) -> String { let (value, unit) = if rate >= 1e12 {(rate/1e12,"TH/s")} else if rate >= 1e9 {(rate/1e9,"GH/s")} else if rate >= 1e6 {(rate/1e6,"MH/s")} else if rate >= 1e3 {(rate/1e3,"KH/s")} else {(rate,"H/s")}; format!("{value:.2} {unit}") }
fn format_duration(seconds: f64) -> String { if !seconds.is_finite() { "—".into() } else if seconds < 60.0 { format!("{seconds:.1}s") } else if seconds < 3600.0 { format!("{:.1}m", seconds/60.0) } else if seconds < 86400.0 { format!("{:.1}h", seconds/3600.0) } else { format!("{:.1}d", seconds/86400.0) } }
fn target_log2(target: Target) -> f64 { let bytes=target.to_be_bytes(); for (i,byte) in bytes.iter().enumerate(){if *byte!=0 { return ((32-i) as f64)*8.0 - f64::from(byte.leading_zeros()) - 1.0; }} 0.0 }
fn expected_seconds(target: Target, rate: f64) -> f64 { if rate <= 0.0 {f64::INFINITY} else {2_f64.powf(256.0-target_log2(target))/rate} }
fn chance_per_minute(target: Target, rate: f64) -> f64 { let expected=expected_seconds(target,rate); if !expected.is_finite() || expected <= 0.0 {0.0} else {1.0-(-60.0/expected).exp()} }

fn nonce_words(nonce: Uint256) -> [u64; 4] { let b=nonce.to_be_bytes(); [u64::from_be_bytes(b[0..8].try_into().unwrap()),u64::from_be_bytes(b[8..16].try_into().unwrap()),u64::from_be_bytes(b[16..24].try_into().unwrap()),u64::from_be_bytes(b[24..32].try_into().unwrap())] }
fn words_to_nonce(words: [u64;4]) -> Uint256 { let mut b=[0_u8;32];for (i,w) in words.into_iter().enumerate(){b[i*8..i*8+8].copy_from_slice(&w.to_be_bytes());}Uint256::from_be_bytes(b) }
