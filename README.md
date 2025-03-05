# Review Club Branch

*This branch was created for the sake of running a review club.*
⚠️ Do not use it for any other purpose, it has a memory leak ⚠️

Things you need to know:
- This branch changes sim-ln to allow running with the "fake" node
  defined in `sim_node.rs`.
- It has a clock speedup hardcoded which speeds up the simulation to 
  produce a lot of payments.
- The sample graph used for this is check in as `simln.json`.

To run simln with the test file:
`make install`
`sim-cli -s simln.json`

Your job it to attach a heap allocation profiler and see the memory leak
in action, and identify the tasks that are building up memory.

Remember that you do not need to review this branch!
It has been provided because the ability to run with "fake" nodes has
not been fully upstreamed to SimLN yet.
