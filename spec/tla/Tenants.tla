---------------------------- MODULE Tenants ----------------------------
(***************************************************************************)
(* A model of tenants and their destruction (ADR-038).                     *)
(*                                                                         *)
(* Multipart.tla and Migrate.tla model the order of requests to the        *)
(* provider.  This module models something else: which keys exist where,   *)
(* and which objects they still open.  A tenant is deleted by destroying   *)
(* its keys, so the question is never whether a request was lost but       *)
(* whether, once the destruction is over, some copy of some key still      *)
(* opens an object it was meant to make unreadable -- or no longer opens   *)
(* one it was not.                                                         *)
(*                                                                         *)
(* Keys live in four kinds of place, and the model has all of them:        *)
(*                                                                         *)
(*   - the keyring file, rewritten by the operator, each write a new       *)
(*     generation;                                                         *)
(*   - every old copy of it -- backups, a Secret's history -- which is     *)
(*     every generation ever written, and opens today with whatever locks  *)
(*     still exist;                                                        *)
(*   - the memory of each gateway instance, which loaded some generation   *)
(*     at its last restart and keeps what it opened until the next;        *)
(*   - the memory of a running `rotate`, which loaded a generation when    *)
(*     it started.                                                        *)
(*                                                                         *)
(* One tenant, T, and the default tenant.  Three buckets: x holds an       *)
(* object on the default tenant's key and joins T; z joins T empty; y      *)
(* stays in the default tenant and is what a destruction must not touch.  *)
(* Two keys: d1, the default tenant's, and t1, T's.  T's section is        *)
(* sealed under lock L1, and a reseal moves it to L2.                      *)
(*                                                                         *)
(* Not in the model: the requests a write or a rotation makes to the       *)
(* provider and their conditions, which Multipart.tla checks; a rotation   *)
(* step here reads and rewrites an object atomically.  Key rotation        *)
(* within a tenant, a second KEK of the same tenant: it changes which of   *)
(* T's keys an object is on, never whether it is on T's.  Names and the    *)
(* audit log: their keys follow the same sections as the KEKs and are      *)
(* shredded with them or not at all.                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Instances,          \* gateway instances
    TwoPhase,           \* a tenant is added inactive and activated once every instance serves it
    CensusRequired,     \* the tombstone needs a census of the tenant's buckets
    CensusGated,        \* the census needs every instance and a running rotate to serve the active tenant
    LockLast,           \* the locks are destroyed after the tombstone has reached every process
    BucketsLeave,       \* a bucket may leave the tenant again
    RotateChecksTenant, \* rotate wraps a bucket's objects only under its own tenant's key
    Reseal,             \* the operator may move T to another lock
    DestroyAllLocks,    \* the destruction names every lock T ever had, not only the current one
    MaxRotations        \* how many rotate runs may start

Buckets  == {"x", "y", "z"}
TBuckets == {"x", "z"}
Kids     == {"d1", "t1"}
Locks    == {"L1", "L2"}
None     == "none"

Perms == Permutations(Instances)

(***************************************************************************)
(* A generation of the keyring file.  hasT: T's section is in it.  tb: the *)
(* buckets the directory assigns to T, kept in the tombstone so that they  *)
(* stay refused.  active: writes to T's buckets use T's key.  tomb: T has  *)
(* been destroyed.  lock: what seals T's section now; locks: every lock    *)
(* that ever has.                                                          *)
(***************************************************************************)
Rec == [hasT: BOOLEAN, tb: SUBSET Buckets, active: BOOLEAN, tomb: BOOLEAN,
        lock: Locks, locks: SUBSET Locks, gen: Nat]

InitRec == [hasT |-> FALSE, tb |-> {}, active |-> FALSE, tomb |-> FALSE,
            lock |-> "L1", locks |-> {}, gen |-> 0]

VARIABLES
    file,           \* the keyring file now
    backups,        \* every earlier generation, still on disk somewhere
    lockAlive,      \* which locks still exist at their key service
    inst,           \* per instance: the generation it loaded and the keys it opened
    rot,            \* the rotate run: running, what it loaded, buckets left
    rotations,      \* rotate runs started so far
    obj,            \* per bucket: the key its object is wrapped under, or None
    censusPassed,   \* the census found every object of T's buckets on T's key
    locksDestroyed  \* the operator has destroyed the locks

vars == <<file, backups, lockAlive, inst, rot, rotations, obj, censusPassed, locksDestroyed>>

(***************************************************************************)
(* What opening a generation yields today.  The default tenant's section   *)
(* is under the deployment lock, which is never destroyed; T's opens only  *)
(* while its lock exists.                                                  *)
(***************************************************************************)
KeysOf(r) == {"d1"} \cup (IF r.hasT /\ lockAlive[r.lock] THEN {"t1"} ELSE {})

Load(r) == [rec |-> r, keys |-> KeysOf(r)]

(* A process refuses T's buckets once T is destroyed, and while it could   *)
(* not open T's section: 403 and 503 in the gateway.                       *)
Serves(l, b) == ~(b \in l.rec.tb /\ (l.rec.tomb \/ (l.rec.hasT /\ "t1" \notin l.keys)))

(* The key a new write to b is wrapped under. *)
WriteKid(l, b) == IF b \in l.rec.tb /\ l.rec.active THEN "t1" ELSE "d1"

(* The key rotate moves b's object onto.  Without the check, it is the     *)
(* key the operator named for the whole run (`--to-kid t1`).               *)
RotateKid(l, b) ==
    IF RotateChecksTenant THEN WriteKid(l, b)
    ELSE IF l.rec.active /\ "t1" \in l.keys THEN "t1" ELSE "d1"

WriteFile(r) == /\ file' = r
                /\ backups' = backups \cup {file}

-----------------------------------------------------------------------------
Init ==
    /\ file = InitRec
    /\ backups = {}
    /\ lockAlive = [l \in Locks |-> TRUE]
    /\ inst = [i \in Instances |-> [rec |-> InitRec, keys |-> {"d1"}]]
    /\ rot = [running |-> FALSE, l |-> [rec |-> InitRec, keys |-> {"d1"}], todo |-> {}]
    /\ rotations = 0
    /\ obj = [b \in Buckets |-> IF b = "z" THEN None ELSE "d1"]
    /\ censusPassed = FALSE
    /\ locksDestroyed = FALSE

(* The operator. *)
AddTenant ==
    /\ ~file.hasT /\ ~file.tomb
    /\ WriteFile([file EXCEPT !.hasT = TRUE, !.tb = TBuckets, !.active = ~TwoPhase,
                              !.locks = {"L1"}, !.gen = @ + 1])
    /\ UNCHANGED <<lockAlive, inst, rot, rotations, obj, censusPassed, locksDestroyed>>

(* Rule 1: activate only once every instance serves the tenant. *)
Activate ==
    /\ TwoPhase /\ file.hasT /\ ~file.active
    /\ \A i \in Instances : inst[i].rec.hasT
    /\ WriteFile([file EXCEPT !.active = TRUE, !.gen = @ + 1])
    /\ UNCHANGED <<lockAlive, inst, rot, rotations, obj, censusPassed, locksDestroyed>>

ResealTenant ==
    /\ Reseal /\ file.hasT /\ file.lock = "L1"
    /\ WriteFile([file EXCEPT !.lock = "L2", !.locks = @ \cup {"L2"}, !.gen = @ + 1])
    /\ UNCHANGED <<lockAlive, inst, rot, rotations, obj, censusPassed, locksDestroyed>>

LeaveTenant ==
    /\ BucketsLeave /\ file.hasT /\ file.active /\ "x" \in file.tb
    /\ WriteFile([file EXCEPT !.tb = @ \ {"x"}, !.gen = @ + 1])
    /\ UNCHANGED <<lockAlive, inst, rot, rotations, obj, censusPassed, locksDestroyed>>

(* Rule 2: count only once nothing can still write T's buckets under      *)
(* another tenant's key -- no instance, and no rotate run, that loaded an  *)
(* earlier generation.                                                     *)
Census ==
    /\ CensusRequired /\ file.hasT /\ file.active /\ ~censusPassed
    /\ CensusGated => /\ \A i \in Instances : inst[i].rec.active
                      /\ rot.running => rot.l.rec.active
    /\ \A b \in file.tb : obj[b] \in {None, "t1"}
    /\ censusPassed' = TRUE
    /\ UNCHANGED <<file, backups, lockAlive, inst, rot, rotations, obj, locksDestroyed>>

Tombstone ==
    /\ file.hasT
    /\ CensusRequired => censusPassed
    /\ WriteFile([file EXCEPT !.hasT = FALSE, !.active = FALSE, !.tomb = TRUE, !.gen = @ + 1])
    /\ UNCHANGED <<lockAlive, inst, rot, rotations, obj, censusPassed, locksDestroyed>>

DestroyLocks ==
    /\ ~locksDestroyed /\ (file.hasT \/ file.tomb)
    /\ LockLast => /\ file.tomb
                   /\ \A i \in Instances : inst[i].rec.tomb
                   /\ rot.running => rot.l.rec.tomb
    /\ LET gone == IF DestroyAllLocks THEN file.locks ELSE {file.lock}
       IN lockAlive' = [l \in Locks |-> lockAlive[l] /\ l \notin gone]
    /\ locksDestroyed' = TRUE
    /\ UNCHANGED <<file, backups, inst, rot, rotations, obj, censusPassed>>

(* The gateway. *)
Restart(i) ==
    /\ inst[i].rec /= file \/ inst[i].keys /= KeysOf(file)
    /\ inst' = [inst EXCEPT ![i] = Load(file)]
    /\ UNCHANGED <<file, backups, lockAlive, rot, rotations, obj, censusPassed, locksDestroyed>>

ClientWrite(i, b) ==
    /\ Serves(inst[i], b)
    /\ obj[b] /= WriteKid(inst[i], b)
    /\ obj' = [obj EXCEPT ![b] = WriteKid(inst[i], b)]
    /\ UNCHANGED <<file, backups, lockAlive, inst, rot, rotations, censusPassed, locksDestroyed>>

(* rotate. *)
RotateStart ==
    /\ ~rot.running /\ rotations < MaxRotations
    /\ rot' = [running |-> TRUE, l |-> Load(file), todo |-> Buckets]
    /\ rotations' = rotations + 1
    /\ UNCHANGED <<file, backups, lockAlive, inst, obj, censusPassed, locksDestroyed>>

RotateStep(b) ==
    /\ rot.running /\ b \in rot.todo
    /\ IF Serves(rot.l, b) /\ obj[b] /= None /\ obj[b] \in rot.l.keys
         THEN obj' = [obj EXCEPT ![b] = RotateKid(rot.l, b)]
         ELSE UNCHANGED obj
    /\ rot' = [rot EXCEPT !.todo = @ \ {b}]
    /\ UNCHANGED <<file, backups, lockAlive, inst, rotations, censusPassed, locksDestroyed>>

(* A run ends when it is done, or dies at any point. *)
RotateStop ==
    /\ rot.running
    /\ rot' = [rot EXCEPT !.running = FALSE, !.todo = {}]
    /\ UNCHANGED <<file, backups, lockAlive, inst, rotations, obj, censusPassed, locksDestroyed>>

Next ==
    \/ AddTenant \/ Activate \/ ResealTenant \/ LeaveTenant
    \/ Census \/ Tombstone \/ DestroyLocks
    \/ \E i \in Instances : Restart(i)
    \/ \E i \in Instances, b \in Buckets : ClientWrite(i, b)
    \/ RotateStart \/ RotateStop \/ \E b \in Buckets : RotateStep(b)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    /\ file \in Rec
    /\ backups \subseteq Rec
    /\ lockAlive \in [Locks -> BOOLEAN]
    /\ \A i \in Instances : inst[i].rec \in Rec /\ inst[i].keys \subseteq Kids
    /\ obj \in [Buckets -> Kids \cup {None}]
    /\ rotations \in 0..MaxRotations

(* Every key that something can still use: any copy of the file, opened    *)
(* with the locks that exist today, and the memory of every process.       *)
Reachable ==
    UNION {KeysOf(r) : r \in backups \cup {file}}
    \cup UNION {inst[i].keys : i \in Instances}
    \cup (IF rot.running THEN rot.l.keys ELSE {})

(* The destruction is over: the locks are destroyed, and every process     *)
(* serves the tombstone.                                                   *)
Finished ==
    /\ locksDestroyed /\ file.tomb
    /\ \A i \in Instances : inst[i].rec.tomb
    /\ rot.running => rot.l.rec.tomb

(* Once it is over, nothing opens an object of T's buckets. *)
Shredded ==
    Finished => \A b \in file.tb : obj[b] = None \/ obj[b] \notin Reachable

(* No object outside T's buckets ever becomes unreadable. *)
NoCollateral ==
    \A b \in Buckets \ file.tb : obj[b] = None \/ obj[b] \in Reachable

(* Until the tombstone is written the destruction can be called off:       *)
(* nothing is unreadable yet.                                              *)
Abortable ==
    ~file.tomb => \A b \in Buckets : obj[b] = None \/ obj[b] \in Reachable

(* An instance that serves a bucket can read the object in it. *)
ReadableEverywhere ==
    \A i \in Instances, b \in Buckets :
        (obj[b] /= None /\ Serves(inst[i], b)) => obj[b] \in inst[i].keys

=============================================================================
