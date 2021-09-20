//use pyo3::class::basic::CompareOp;
//use pyo3::create_exception;
//use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
//use pyo3::pyclass::PyClass;
//use pyo3::types::{PyBytes, PyUnicode};
//use pyo3::wrap_pyfunction;
//use pyo3::PyObjectProtocol;

use nucypher_core;

#[pyclass(module = "nucypher_core")]
pub struct ReencryptionRequest {
    backend: nucypher_core::ReencryptionRequest,
}

#[pyclass(module = "nucypher_core")]
pub struct ReencryptionResponse {
    backend: nucypher_core::ReencryptionResponse,
}

/// A Python module implemented in Rust.
#[pymodule]
fn _nucypher_core(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ReencryptionRequest>()?;
    m.add_class::<ReencryptionResponse>()?;
    Ok(())
}
