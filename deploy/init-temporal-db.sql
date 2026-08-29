-- Temporal keeps its own schemas; sharing the Postgres instance rather than running a
-- second one is a deliberate memory trade on an 8 GB host.
CREATE DATABASE temporal;
CREATE DATABASE temporal_visibility;
