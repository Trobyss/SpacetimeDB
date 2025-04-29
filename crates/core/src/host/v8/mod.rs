use std::mem;
use std::rc::Rc;
use std::sync::{Arc, LazyLock};

use crate::database_logger::{DatabaseLogger, SystemLogger};
use crate::db::datastore::locking_tx_datastore::MutTxId;
use crate::db::datastore::traits::Program;
use crate::energy::EnergyMonitor;
use crate::module_host_context::ModuleCreationContext;
use crate::replica_context::ReplicaContext;

use super::instance_env::InstanceEnv;
use super::module_host::{CallReducerParams, Module, ModuleInfo, ModuleInstance};
use super::{ReducerCallResult, Scheduler, UpdateDatabaseResult};

mod util;

use indexmap::IndexMap;
use itertools::Itertools;
use prometheus::register;
use util::{
    ascii_str, module, scratch_buf, strings, throw, CallbackResult, ErrorOrException, ExceptionOptionExt,
    ExceptionThrown, ThrowExceptionResultExt, TypeError,
};

struct V8InstanceEnv {
    instance_env: InstanceEnv,
}

pub struct JsModule {
    replica_context: Arc<ReplicaContext>,
    scheduler: Scheduler,
    info: Arc<ModuleInfo>,
    energy_monitor: Arc<dyn EnergyMonitor>,
    snapshot: Arc<[u8]>,
    module_idx: usize,
}

pub fn compile_real(mcc: ModuleCreationContext) -> anyhow::Result<JsModule> {
    let program = std::str::from_utf8(&mcc.program.bytes)?;
    let (snapshot, module_idx) = compile(program, Arc::new(Logger))?;
    Ok(JsModule {
        replica_context: mcc.replica_ctx,
        scheduler: mcc.scheduler,
        info: todo!(),
        energy_monitor: mcc.energy_monitor,
        snapshot,
        module_idx,
    })
}

#[derive(thiserror::Error, Debug)]
#[error("js error: {msg:?}")]
struct JsError {
    msg: String,
}

impl JsError {
    fn from_caught(scope: &mut v8::TryCatch<'_, v8::HandleScope<'_>>) -> Self {
        match scope.message() {
            Some(msg) => Self {
                msg: msg.get(scope).to_rust_string_lossy(scope),
            },
            None => Self {
                msg: "unknown error".to_owned(),
            },
        }
    }
}

fn catch_exception<'s, T>(
    scope: &mut v8::HandleScope<'s>,
    f: impl FnOnce(&mut v8::HandleScope<'s>) -> Result<T, ErrorOrException>,
) -> Result<T, ErrorOrException<JsError>> {
    let scope = &mut v8::TryCatch::new(scope);
    f(scope).map_err(|e| match e {
        ErrorOrException::Err(e) => ErrorOrException::Err(e),
        ErrorOrException::Exception(ExceptionThrown) => ErrorOrException::Exception(JsError::from_caught(scope)),
    })
}

struct Logger;
impl Logger {
    fn log(&self, x: &str) {
        eprint!("{x}")
    }
}

struct ModuleBuilder {
    reducers: IndexMap<String, v8::Global<v8::Function>>,
}

fn compile(program: &str, logger: Arc<Logger>) -> anyhow::Result<(Arc<[u8]>, usize)> {
    let isolate = v8::Isolate::snapshot_creator(Some(&EXTERN_REFS), None);
    let mut isolate = scopeguard::guard(isolate, |isolate| {
        // rusty_v8 panics if we don't call this when dropping isolate
        isolate.create_blob(v8::FunctionCodeHandling::Keep);
    });
    isolate.set_slot(ModuleBuilder {
        reducers: IndexMap::default(),
    });
    let module_idx;
    {
        let isolate = &mut *isolate;
        let handle_scope = &mut v8::HandleScope::new(isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let scope = &mut v8::ContextScope::new(handle_scope, context);
        scope.set_default_context(context);
        // scope.get_current_context().set_slot(logger);
        let module = catch_exception(scope, |scope| init_module(scope, program))?;
        module_idx = scope.add_context_data(context, module);
    }

    let snapshot = scopeguard::ScopeGuard::into_inner(isolate)
        .create_blob(v8::FunctionCodeHandling::Keep)
        .unwrap();
    // d923b61bd4a4a000589af55b9ac5f046e97c4c756c96427fbc24d1253e7c9c77
    dbg!(module_idx, spacetimedb_lib::hash_bytes(&snapshot));
    let snapshot = <Arc<[u8]>>::from(&*snapshot);

    Ok((snapshot, module_idx))
}

fn init_module<'s>(
    scope: &mut v8::HandleScope<'s>,
    program: &str,
) -> Result<v8::Local<'s, v8::Module>, ErrorOrException> {
    let source = v8::String::new_from_utf8(scope, program.as_bytes(), v8::NewStringType::Normal).err()?;
    let null = v8::null(scope).into();
    let source = &mut v8::script_compiler::Source::new(
        source,
        Some(&v8::ScriptOrigin::new(
            scope, null, 0, 0, false, 0, None, false, false, true, None,
        )),
    );
    let module = v8::script_compiler::compile_module(scope, source).err()?;

    let x = module.instantiate_module(scope, resolve_module).err();
    x?;

    module.evaluate(scope).err()?;

    Ok(module)
}

fn resolve_module<'s>(
    context: v8::Local<'s, v8::Context>,
    spec: v8::Local<'s, v8::String>,
    _attrs: v8::Local<'s, v8::FixedArray>,
    _referrer: v8::Local<'s, v8::Module>,
) -> Option<v8::Local<'s, v8::Module>> {
    let scope = &mut *unsafe { v8::CallbackScope::new(context) };
    let mut buf = scratch_buf::<32>();
    let spec_str = spec.to_rust_cow_lossy(scope, &mut buf);
    match &*spec_str {
        spacetime_sys_10_0::SPEC => Some(spacetime_sys_10_0::make(scope)),
        _ => {
            let msg = v8::String::new(scope, &format!("Could not find module {spec_str:?}")).unwrap();
            let exc = v8::Exception::type_error(scope, msg);
            scope.throw_exception(exc);
            None
        }
    }
}

module!(
    spacetime_sys_10_0 = "spacetime:sys/v10.0",
    function(console_log),
    function(register_reducer),
);

static EXTERN_REFS: LazyLock<v8::ExternalReferences> =
    LazyLock::new(|| v8::ExternalReferences::new(&spacetime_sys_10_0::external_refs().collect_vec()));

fn console_log(scope: &mut v8::HandleScope<'_>, args: v8::FunctionCallbackArguments<'_>) -> CallbackResult<()> {
    // let logger = scope.get_current_context().get_slot::<Arc<Logger>>().unwrap().clone();
    let s: String = (0..args.length())
        .map(|i| args.get(i).to_rust_string_lossy(scope))
        .collect();
    eprintln!("{s}");
    // logger.log(&s);
    Ok(())
}

fn register_reducer(scope: &mut v8::HandleScope<'_>, args: v8::FunctionCallbackArguments<'_>) -> CallbackResult<()> {
    if scope.get_slot::<ModuleBuilder>().is_none() {
        throw(scope, TypeError(ascii_str!("You cannot dynamically register reducers")))?;
    }

    let name = args
        .get(0)
        .try_cast::<v8::String>()
        .map_err(|_| TypeError(ascii_str!("First argument to register_reducer must be string")))
        .throw(scope)?
        .to_rust_string_lossy(scope);

    let function = args
        .get(0)
        .try_cast::<v8::Function>()
        .map_err(|_| TypeError(ascii_str!("First argument to register_reducer must be function")))
        .throw(scope)?;
    let function = v8::Global::new(scope, function);

    let module = scope.get_slot_mut::<ModuleBuilder>().unwrap();
    match module.reducers.entry(name) {
        indexmap::map::Entry::Vacant(v) => {
            v.insert(function);
        }
        indexmap::map::Entry::Occupied(o) => {
            let msg = format!("Reducer {:?} already registered", o.key());
            throw(scope, TypeError(msg))?;
        }
    }

    Ok(())
}

#[test]
fn v8_compile_test() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();
    let program = r#"
import {console_log} from "spacetime:sys/v10.0";
function hello() {
    console_log(console_log("abcd", "efg"));
}
hello()
"#;
    let (snapshot, module_idx) = compile(program, Arc::new(Logger)).unwrap();
    // dbg!(module_idx, bytes::Bytes::copy_from_slice(&snapshot));
    // panic!();
}

impl Module for JsModule {
    type Instance = JsInstance;

    type InitialInstances<'a> = std::iter::Empty<JsInstance>;

    fn initial_instances(&mut self) -> Self::InitialInstances<'_> {
        std::iter::empty()
    }

    fn info(&self) -> Arc<ModuleInfo> {
        self.info.clone()
    }

    fn create_instance(&self) -> Self::Instance {
        todo!()
    }

    fn replica_ctx(&self) -> &ReplicaContext {
        &self.replica_context
    }

    fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }
}

pub struct JsInstance {}

impl ModuleInstance for JsInstance {
    fn trapped(&self) -> bool {
        false
    }

    fn init_database(&mut self, program: Program) -> anyhow::Result<Option<ReducerCallResult>> {
        todo!()
    }

    fn update_database(
        &mut self,
        program: Program,
        old_module_info: Arc<ModuleInfo>,
    ) -> anyhow::Result<UpdateDatabaseResult> {
        todo!()
    }

    fn call_reducer(&mut self, tx: Option<MutTxId>, params: CallReducerParams) -> ReducerCallResult {
        todo!()
    }
}
