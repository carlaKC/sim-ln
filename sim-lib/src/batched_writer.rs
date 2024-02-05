use csv::{Writer, WriterBuilder};
use serde::Serialize;
use std::fs::File;
use std::path::PathBuf;

use crate::SimulationError;

pub struct BatchedWriter {
    batch_size: u32,
    counter: u32,
    writer: Writer<File>,
}

impl BatchedWriter {
    /// Creates a new writer and the results file that output will be written to.
    pub fn new(
        directory: PathBuf,
        file_name: String,
        batch_size: u32,
    ) -> Result<BatchedWriter, SimulationError> {
        let file = directory.join(file_name);

        let writer = WriterBuilder::new()
            .from_path(file)
            .map_err(SimulationError::CsvError)?;

        Ok(BatchedWriter {
            batch_size,
            counter: 1,
            writer,
        })
    }

    /// Adds an item to the batch to be written, flushing to disk if the batch size has been reached.
    pub fn queue<S: Serialize>(&mut self, record: S) -> Result<(), SimulationError> {
        // If there's an error serializing an input, flush and exit with an error.
        self.writer.serialize(record).map_err(|e| {
            // If we encounter another errors (when we've already failed to serialize), we just log because we've
            // already experienced a critical error.
            if let Err(e) = self.write(true) {
                log::error!("Error flushing to disk: {e}");
            }

            SimulationError::CsvError(e)
        })?;

        // Otherwise increment counter and flush if we've reached batch size.
        self.counter = self.counter % self.batch_size + 1;
        self.write(false)
    }

    /// Writes the contents of the batched writer to disk. Will result in a write if force is true _or_ the batch is
    /// full.
    pub fn write(&mut self, force: bool) -> Result<(), SimulationError> {
        if force {
            return self
                .writer
                .flush()
                .map_err(|e| SimulationError::CsvError(e.into()));
        }

        if self.batch_size == self.counter {
            return self
                .writer
                .flush()
                .map_err(|e| SimulationError::CsvError(e.into()));
        }

        Ok(())
    }
}
