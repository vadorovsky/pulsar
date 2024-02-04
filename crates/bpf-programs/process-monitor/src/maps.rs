const MAX_IMAGE_LEN: usize = 100;
const MAX_CGROUP_LEN: usize = 300;

const MAX_PREEMPTION_NESTING_LEVEL: u32 = 3;

use aya_bpf::{
    cty::{c_char, c_int},
    macros::map,
    maps::{Array, HashMap, PerCpuArray, PerfEventArray},
};

use process_monitor_events::ProcessEvent;

#[allow(non_upper_case_globals)]
#[map]
pub(crate) static m_rules: HashMap<[c_char; MAX_IMAGE_LEN], u8> = HashMap::with_max_entries(100, 0);

#[allow(non_upper_case_globals)]
#[map]
pub(crate) static m_cgroup_rules: HashMap<[c_char; MAX_CGROUP_LEN], u8> =
    HashMap::with_max_entries(100, 0);

#[allow(non_upper_case_globals)]
#[map]
pub(crate) static m_interest: HashMap<c_int, c_char> = HashMap::with_max_entries(16384, 0);

#[allow(non_upper_case_globals)]
#[map]
pub(crate) static init_map: Array<u32> = Array::with_max_entries(1, 0);

#[allow(non_upper_case_globals)]
#[map]
pub(crate) static map_temp_process_event: PerCpuArray<ProcessEvent> =
    PerCpuArray::with_max_entries(MAX_PREEMPTION_NESTING_LEVEL, 0);

#[allow(non_upper_case_globals)]
#[map]
pub(crate) static map_nesting_process_event: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[allow(non_upper_case_globals)]
#[map]
pub(crate) static map_output_process_event: PerfEventArray<ProcessEvent> =
    PerfEventArray::with_max_entries(1024, 0);
