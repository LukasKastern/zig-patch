rework patch generation for maximum speeeeeed

Each file is assigned an OperationData structure containing:
    -> The last operation of the last work unit   
    -> The last partial block of the last work unit 

Patch generation is split into Work Units.
Each unit of work generates a partial patch of a certain file.

The buffer that a unit operates upon is populated using AsyncIO on the main thread.

Once the buffer is ready the unit is scheduled to a worker thread. 
When that unit completes the generated data is written to a file. 


