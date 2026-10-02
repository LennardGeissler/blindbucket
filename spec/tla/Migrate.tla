---------------------------- MODULE Migrate ----------------------------
(***************************************************************************)
(* A model of `blindbucket migrate-names`, which moves objects written     *)
(* with object-name encryption off to the keys they have with it on        *)
(* (ADR-015, ADR-022).                                                     *)
(*                                                                         *)
(* Multipart.tla models one stored key, because everything it checks is   *)
(* per key.  A migration is the one operation that is not: it moves an     *)
(* object from the key P a client named, stored in clear, to E(P), the     *)
(* key the same client name maps to once names are encrypted.  So this     *)
(* model has two stored keys for one object identity, and that is the      *)
(* whole reason it is a module of its own rather than more of the other    *)
(* one -- a second key would multiply a state space that already takes    *)
(* twenty CPU-minutes, to check rules that do not change.                  *)
(*                                                                         *)
(* The gateway serves with names encrypted throughout (ADR-022): clients   *)
(* read, write and delete at E(P) only, and P is visible to nothing but    *)
(* the migration.  An object the migration has not reached yet is          *)
(* therefore invisible, which is the price of running the migration        *)
(* without a transitional gateway mode, and not something checked here.    *)
(*                                                                         *)
(* Every run, and every client, may die after any step, as in              *)
(* Multipart.tla.  Two runs exist so that a second run can be the restart  *)
(* of a first that died -- "the copy is written, the key in clear is not   *)
(* deleted yet, the run stops" -- and, in the same model, two operators    *)
(* starting the command at once.                                           *)
(*                                                                         *)
(* Invariants under check:                                                 *)
(*                                                                         *)
(*   I1            Every visible multipart object, at either key, has a    *)
(*                 manifest with its manifest id.                          *)
(*                                                                         *)
(*   NoLostWrite   The newest write to the object still exists somewhere: *)
(*                 at E(P), or at P while the migration has not reached   *)
(*                 it.  This is I2 of Multipart.tla widened to two keys:   *)
(*                 a migration that copies over a client's write, or       *)
(*                 deletes a version it never copied, breaks it.           *)
(*                                                                         *)
(*   NoLostDelete  An object a client deleted does not come back.          *)
(*                                                                         *)
(*   Converged     Once every run has stopped and one of them finished     *)
(*                 cleanly, nothing is left at P.  Without it, a           *)
(*                 migration that never deletes anything satisfies the     *)
(*                 three above.                                            *)
(***************************************************************************)
EXTENDS FiniteSets, TLC

CONSTANTS
    Runs,          \* The migration runs, e.g. {r1, r2}.

    CreateGuard,   \* The write that publishes the copy at E(P).
                   \*   "ifnonematch" - If-None-Match: * on the completion
                   \*   "none"        - unconditional

    ExistingEnc,   \* What a run makes of an object it finds at E(P).
                   \*   "obsolete" - P is obsolete: delete it
                   \*   "conflict" - leave P in place and report a conflict

    DeleteGuard,   \* The delete of P.
                   \*   "ifmatch" - If-Match on the ETag read at the start
                   \*   "none"    - unconditional

    ClientWrites,  \* A PUT and a multipart upload through the gateway.
    ClientDeletes, \* A DELETE through the gateway.
    StaleWriter    \* A gateway instance still serving names in clear,
                   \* which writes to P.  ADR-022 makes its absence a
                   \* precondition; this is the configuration that says why.

Plain == "plain"   \* the stored key P, in clear
Enc   == "enc"     \* the stored key E(P)
Keys  == {Plain, Enc}

\* An object version is told apart by its data key, as in the code: a copy
\* keeps the data key (ADR-012) and every client write generates a new one.
\* Manifest ids are minted per published version (R1), and each process
\* publishes at most once, so a process's name serves as its manifest id.
NoMid    == "nil"
NoDek    == "none"
InitMid  == "m0"       \* the manifest of the object the model starts from
InitDek  == "d0"       \* and its data key
PutDek   == "put"
UpId     == "up"       \* the client upload: process, manifest id, data key
StaleDek == "stale"
Deleted  == "deleted"

Mids  == Runs \cup {InitMid, UpId}
Deks  == {InitDek, PutDek, UpId, StaleDek}
Kinds == {"absent", "single", "multi"}

Absent == [kind |-> "absent", mid |-> NoMid, dek |-> NoDek]

ASSUME CreateGuard \in {"ifnonematch", "none"}
ASSUME ExistingEnc \in {"obsolete", "conflict"}
ASSUME DeleteGuard \in {"ifmatch", "none"}
ASSUME {ClientWrites, ClientDeletes, StaleWriter} \subseteq BOOLEAN

\* The runs are interchangeable: nothing in the algorithm or the invariants
\* tells one from the other.
Perms == Permutations(Runs)

(*--algorithm migrate {

variables
    \* What is visible at each stored key.  The object starts in clear and
    \* multipart, the shape that has a manifest to move along with it.
    obj = [k \in Keys |-> IF k = Plain
                          THEN [kind |-> "multi", mid |-> InitMid, dek |-> InitDek]
                          ELSE Absent],

    \* The manifest sidecars under each key's manifest prefix.  A manifest is
    \* bound to the stored key, so moving an object means a new manifest
    \* under E(P) and an orphan under P.
    manifests = [k \in Keys |-> IF k = Plain THEN {InitMid} ELSE {}],

    \* Open multipart uploads.  Every upload in this model is at E(P): the
    \* migration's copies and the client's upload.  Nothing uploads to P.
    openUploads = {},

    \* History, not system state: the data key of the newest write to the
    \* object, or Deleted.  A copy is not a write -- it moves a version, it
    \* does not make one.
    latest = InitDek,

    \* History: run r stopped at the end of its algorithm, not by dying.
    cleanEnd = [r \in Runs |-> FALSE];

define {
    MidOf(k)     == IF obj[k].kind = "multi" THEN obj[k].mid ELSE NoMid
    UploadsAt(k) == IF k = Enc THEN openUploads ELSE {}
    GcKey(g)     == IF g = "gcPlain" THEN Plain ELSE Enc

    TypeOK ==
        /\ \A k \in Keys :
              /\ obj[k].kind \in Kinds
              /\ obj[k].mid  \in Mids \cup {NoMid}
              /\ obj[k].dek  \in Deks \cup {NoDek}
              /\ manifests[k] \subseteq Mids
        /\ openUploads \subseteq Runs \cup {UpId}
        /\ latest \in Deks \cup {Deleted}
        /\ cleanEnd \in [Runs -> BOOLEAN]

    I1 == \A k \in Keys : obj[k].kind = "multi" => obj[k].mid \in manifests[k]

    NoLostWrite ==
        latest # Deleted =>
            \E k \in Keys : obj[k].kind # "absent" /\ obj[k].dek = latest

    NoLostDelete == latest = Deleted => obj[Enc].kind = "absent"

    Converged ==
        ( /\ \A r \in Runs : pc[r] = "Done"
          /\ \E r \in Runs : cleanEnd[r] )
        => obj[Plain].kind = "absent"
}

\* What a run read about P is local state; a crash loses it.
macro forget() {
    srcDek := NoDek; srcMid := NoMid; srcKind := "absent";
}

(*************************************************************************)
(* One run of `blindbucket migrate-names`, on the one object.  The steps *)
(* are those of internal/migrate, and the labels are the hook names its  *)
(* integration tests hold a run at.                                       *)
(*************************************************************************)
process (Mig \in Runs)
    variables srcDek = NoDek, srcMid = NoMid, srcKind = "absent";
{
  migHeadPlain:
    \* HEAD P.  Absent means there is nothing to move: a run before this one
    \* finished it, or never needed to.
    either {
        if (obj[Plain].kind = "absent") {
            cleanEnd[self] := TRUE;
            goto Done;
        } else {
            srcDek  := obj[Plain].dek;
            srcMid  := MidOf(Plain);
            srcKind := obj[Plain].kind;
        };
    }
    or { goto Done; };

  migHeadEnc:
    \* HEAD E(P).  Something already there is either a copy of P that a run
    \* published and then died before deleting P -- the same data key -- or
    \* a client's write through the gateway since it began serving
    \* encrypted names, which is newer than anything at P.  Both make P
    \* obsolete.  The code compares the data keys to say which of the two
    \* it was; the model has one branch, because the answer changes what a
    \* run reports and not what it does.
    either {
        if (obj[Enc].kind = "absent") {
            skip;
        } else {
            if (ExistingEnc = "conflict") {
                \* The cautious-looking alternative: never delete P unless
                \* this run has just copied it itself.
                forget();
                cleanEnd[self] := TRUE;
                goto Done;
            } else {
                goto migDelete;
            };
        };
    }
    or { forget(); goto Done; };

  migCreate:
    either { openUploads := openUploads \cup {self}; }
    or     { forget(); goto Done; };

  migCopy:
    \* UploadPartCopy, with x-amz-copy-source-if-match on the ETag read at
    \* migHeadPlain.  objcopy always sends it; a source that changed or went
    \* away -- another run deleted it -- is refused, and the run starts
    \* over on the object.
    either {
        if (obj[Plain].kind = "absent" \/ obj[Plain].dek # srcDek) {
            openUploads := openUploads \ {self};
            forget();
            goto migHeadPlain;
        };
    }
    or { forget(); goto Done; };

  migManifest:
    \* R2: the manifest under E(P) exists before the object that names it.
    either {
        if (srcKind = "multi") { manifests[Enc] := manifests[Enc] \cup {self}; };
    }
    or { forget(); goto Done; };

  migComplete:
    either {
        if (self \notin openUploads) {
            \* The lifecycle rule aborted the upload: the object is reported
            \* as failed, and the manifest just written is an orphan for gc.
            forget();
            goto Done;
        } else {
            if (CreateGuard = "ifnonematch" /\ obj[Enc].kind # "absent") {
                \* 412: something reached E(P) since migHeadEnc -- a client,
                \* or the other run.  Read it again rather than give up:
                \* either way it makes P obsolete.
                openUploads := openUploads \ {self};
                goto migHeadEnc;
            } else {
                openUploads := openUploads \ {self};
                obj[Enc] := [kind |-> srcKind,
                             mid  |-> IF srcKind = "multi" THEN self ELSE NoMid,
                             dek  |-> srcDek];
            };
        };
    }
    or { forget(); goto Done; };

  migDelete:
    \* Delete P.  This is the step the abort the model was written for falls
    \* just before: a run that dies here has published the copy and left P.
    either {
        if (DeleteGuard = "ifmatch"
            /\ (obj[Plain].kind = "absent" \/ obj[Plain].dek # srcDek)) {
            \* 412: P changed since migHeadPlain.  Start over on it.
            forget();
            goto migHeadPlain;
        } else {
            obj[Plain] := Absent;
        };
    }
    or { forget(); goto Done; };

  migManifestDel:
    \* R3: only now, and only the manifest id observed at migHeadPlain.  A
    \* failure here leaves an orphan under P for gc, not a broken object.
    either {
        if (srcMid # NoMid) { manifests[Plain] := manifests[Plain] \ {srcMid}; };
    }
    or { skip; };
    cleanEnd[self] := TRUE;
    forget();
}

(*************************************************************************)
(* A client PUT through the gateway, which serves encrypted names and so  *)
(* writes E(P).  Last writer wins, unconditionally, as in S3.             *)
(*************************************************************************)
process (Put = "put")
{
  putWrite:
    either {
        await ClientWrites;
        obj[Enc] := [kind |-> "single", mid |-> NoMid, dek |-> PutDek];
        latest := PutDek;
    }
    or { skip; };
}

(*************************************************************************)
(* A client multipart upload to E(P), in the completion order of R1-R3,   *)
(* as Multipart.tla models it.  It is here because the migration's own    *)
(* copy is a multipart upload to the same key, and the manifests the two  *)
(* write have to survive each other and gc.                               *)
(*************************************************************************)
process (Up = UpId)
    variables upObserved = NoMid;
{
  upCreate:
    either { await ClientWrites; openUploads := openUploads \cup {UpId}; }
    or     { goto Done; };

  upHead:
    either { upObserved := MidOf(Enc); }
    or     { goto Done; };

  upManifest:
    either { manifests[Enc] := manifests[Enc] \cup {UpId}; }
    or     { upObserved := NoMid; goto Done; };

  upComplete:
    either {
        if (UpId \notin openUploads) {
            upObserved := NoMid;
            goto Done;
        } else {
            openUploads := openUploads \ {UpId};
            obj[Enc] := [kind |-> "multi", mid |-> UpId, dek |-> UpId];
            latest := UpId;
        };
    }
    or { upObserved := NoMid; goto Done; };

  upCleanup:
    either {
        if (upObserved # NoMid) { manifests[Enc] := manifests[Enc] \ {upObserved}; };
    }
    or { skip; };
    upObserved := NoMid;
}

(*************************************************************************)
(* A client DELETE through the gateway.  It reaches E(P) and nothing      *)
(* else: the gateway does not know that a migration is under way, and     *)
(* ADR-022 gives it no mode in which it would.                            *)
(*************************************************************************)
process (Del = "del")
    variables delObserved = NoMid;
{
  delHead:
    either { await ClientDeletes; delObserved := MidOf(Enc); }
    or     { goto Done; };

  delRemove:
    either { obj[Enc] := Absent; latest := Deleted; }
    or     { delObserved := NoMid; goto Done; };

  delManifest:
    either {
        if (delObserved # NoMid) { manifests[Enc] := manifests[Enc] \ {delObserved}; };
    }
    or { skip; };
    delObserved := NoMid;
}

(*************************************************************************)
(* A gateway instance that still serves names in clear -- one not yet     *)
(* restarted with the new configuration -- writing P.                     *)
(*************************************************************************)
process (Stale = "stale")
{
  staleWrite:
    either {
        await StaleWriter;
        obj[Plain] := [kind |-> "single", mid |-> NoMid, dek |-> StaleDek];
        latest := StaleDek;
    }
    or { skip; };
}

(*************************************************************************)
(* The lifecycle rule for incomplete uploads, as in Multipart.tla.        *)
(*************************************************************************)
process (Life = "lifecycle")
{
  lifeAbort:
    while (TRUE) {
        with (u \in openUploads) { openUploads := openUploads \ {u}; };
    };
}

(*************************************************************************)
(* One gc pass over each stored key, in the order of R4.  gc never needs  *)
(* the name key: it works in the provider's namespace, which is why the   *)
(* orphan a migration leaves under P is collected like any other.         *)
(*************************************************************************)
process (Gc \in {"gcPlain", "gcEnc"})
    variables seen = {}, current = NoMid;
{
  gcList:
    either { seen := manifests[GcKey(self)]; }
    or     { goto Done; };

  gcUploads:
    either { if (UploadsAt(GcKey(self)) # {}) { seen := {}; goto Done; }; }
    or     { seen := {}; goto Done; };

  gcHead:
    either { current := MidOf(GcKey(self)); }
    or     { seen := {}; goto Done; };

  gcDelete:
    either { manifests[GcKey(self)] := manifests[GcKey(self)] \ (seen \ {current}); }
    or     { skip; };
    seen := {};
    current := NoMid;
}

}
*)
\* BEGIN TRANSLATION
VARIABLES obj, manifests, openUploads, latest, cleanEnd, pc

(* define statement *)
MidOf(k)     == IF obj[k].kind = "multi" THEN obj[k].mid ELSE NoMid
UploadsAt(k) == IF k = Enc THEN openUploads ELSE {}
GcKey(g)     == IF g = "gcPlain" THEN Plain ELSE Enc

TypeOK ==
    /\ \A k \in Keys :
          /\ obj[k].kind \in Kinds
          /\ obj[k].mid  \in Mids \cup {NoMid}
          /\ obj[k].dek  \in Deks \cup {NoDek}
          /\ manifests[k] \subseteq Mids
    /\ openUploads \subseteq Runs \cup {UpId}
    /\ latest \in Deks \cup {Deleted}
    /\ cleanEnd \in [Runs -> BOOLEAN]

I1 == \A k \in Keys : obj[k].kind = "multi" => obj[k].mid \in manifests[k]

NoLostWrite ==
    latest # Deleted =>
        \E k \in Keys : obj[k].kind # "absent" /\ obj[k].dek = latest

NoLostDelete == latest = Deleted => obj[Enc].kind = "absent"

Converged ==
    ( /\ \A r \in Runs : pc[r] = "Done"
      /\ \E r \in Runs : cleanEnd[r] )
    => obj[Plain].kind = "absent"

VARIABLES srcDek, srcMid, srcKind, upObserved, delObserved, seen, current

vars == << obj, manifests, openUploads, latest, cleanEnd, pc, srcDek, srcMid, 
           srcKind, upObserved, delObserved, seen, current >>

ProcSet == (Runs) \cup {"put"} \cup {UpId} \cup {"del"} \cup {"stale"} \cup {"lifecycle"} \cup ({"gcPlain", "gcEnc"})

Init == (* Global variables *)
        /\ obj = [k \in Keys |-> IF k = Plain
                                 THEN [kind |-> "multi", mid |-> InitMid, dek |-> InitDek]
                                 ELSE Absent]
        /\ manifests = [k \in Keys |-> IF k = Plain THEN {InitMid} ELSE {}]
        /\ openUploads = {}
        /\ latest = InitDek
        /\ cleanEnd = [r \in Runs |-> FALSE]
        (* Process Mig *)
        /\ srcDek = [self \in Runs |-> NoDek]
        /\ srcMid = [self \in Runs |-> NoMid]
        /\ srcKind = [self \in Runs |-> "absent"]
        (* Process Up *)
        /\ upObserved = NoMid
        (* Process Del *)
        /\ delObserved = NoMid
        (* Process Gc *)
        /\ seen = [self \in {"gcPlain", "gcEnc"} |-> {}]
        /\ current = [self \in {"gcPlain", "gcEnc"} |-> NoMid]
        /\ pc = [self \in ProcSet |-> CASE self \in Runs -> "migHeadPlain"
                                        [] self = "put" -> "putWrite"
                                        [] self = UpId -> "upCreate"
                                        [] self = "del" -> "delHead"
                                        [] self = "stale" -> "staleWrite"
                                        [] self = "lifecycle" -> "lifeAbort"
                                        [] self \in {"gcPlain", "gcEnc"} -> "gcList"]

migHeadPlain(self) == /\ pc[self] = "migHeadPlain"
                      /\ \/ /\ IF obj[Plain].kind = "absent"
                                  THEN /\ cleanEnd' = [cleanEnd EXCEPT ![self] = TRUE]
                                       /\ pc' = [pc EXCEPT ![self] = "Done"]
                                       /\ UNCHANGED << srcDek, srcMid, srcKind >>
                                  ELSE /\ srcDek' = [srcDek EXCEPT ![self] = obj[Plain].dek]
                                       /\ srcMid' = [srcMid EXCEPT ![self] = MidOf(Plain)]
                                       /\ srcKind' = [srcKind EXCEPT ![self] = obj[Plain].kind]
                                       /\ pc' = [pc EXCEPT ![self] = "migHeadEnc"]
                                       /\ UNCHANGED cleanEnd
                         \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                            /\ UNCHANGED <<cleanEnd, srcDek, srcMid, srcKind>>
                      /\ UNCHANGED << obj, manifests, openUploads, latest, 
                                      upObserved, delObserved, seen, current >>

migHeadEnc(self) == /\ pc[self] = "migHeadEnc"
                    /\ \/ /\ IF obj[Enc].kind = "absent"
                                THEN /\ TRUE
                                     /\ pc' = [pc EXCEPT ![self] = "migCreate"]
                                     /\ UNCHANGED << cleanEnd, srcDek, srcMid, 
                                                     srcKind >>
                                ELSE /\ IF ExistingEnc = "conflict"
                                           THEN /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                                                /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                                                /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                                                /\ cleanEnd' = [cleanEnd EXCEPT ![self] = TRUE]
                                                /\ pc' = [pc EXCEPT ![self] = "Done"]
                                           ELSE /\ pc' = [pc EXCEPT ![self] = "migDelete"]
                                                /\ UNCHANGED << cleanEnd, 
                                                                srcDek, srcMid, 
                                                                srcKind >>
                       \/ /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                          /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                          /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                          /\ pc' = [pc EXCEPT ![self] = "Done"]
                          /\ UNCHANGED cleanEnd
                    /\ UNCHANGED << obj, manifests, openUploads, latest, 
                                    upObserved, delObserved, seen, current >>

migCreate(self) == /\ pc[self] = "migCreate"
                   /\ \/ /\ openUploads' = (openUploads \cup {self})
                         /\ pc' = [pc EXCEPT ![self] = "migCopy"]
                         /\ UNCHANGED <<srcDek, srcMid, srcKind>>
                      \/ /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                         /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                         /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                         /\ pc' = [pc EXCEPT ![self] = "Done"]
                         /\ UNCHANGED openUploads
                   /\ UNCHANGED << obj, manifests, latest, cleanEnd, 
                                   upObserved, delObserved, seen, current >>

migCopy(self) == /\ pc[self] = "migCopy"
                 /\ \/ /\ IF obj[Plain].kind = "absent" \/ obj[Plain].dek # srcDek[self]
                             THEN /\ openUploads' = openUploads \ {self}
                                  /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                                  /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                                  /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                                  /\ pc' = [pc EXCEPT ![self] = "migHeadPlain"]
                             ELSE /\ pc' = [pc EXCEPT ![self] = "migManifest"]
                                  /\ UNCHANGED << openUploads, srcDek, srcMid, 
                                                  srcKind >>
                    \/ /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                       /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                       /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                       /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ UNCHANGED openUploads
                 /\ UNCHANGED << obj, manifests, latest, cleanEnd, upObserved, 
                                 delObserved, seen, current >>

migManifest(self) == /\ pc[self] = "migManifest"
                     /\ \/ /\ IF srcKind[self] = "multi"
                                 THEN /\ manifests' = [manifests EXCEPT ![Enc] = manifests[Enc] \cup {self}]
                                 ELSE /\ TRUE
                                      /\ UNCHANGED manifests
                           /\ pc' = [pc EXCEPT ![self] = "migComplete"]
                           /\ UNCHANGED <<srcDek, srcMid, srcKind>>
                        \/ /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                           /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                           /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                           /\ pc' = [pc EXCEPT ![self] = "Done"]
                           /\ UNCHANGED manifests
                     /\ UNCHANGED << obj, openUploads, latest, cleanEnd, 
                                     upObserved, delObserved, seen, current >>

migComplete(self) == /\ pc[self] = "migComplete"
                     /\ \/ /\ IF self \notin openUploads
                                 THEN /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                                      /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                                      /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                                      /\ pc' = [pc EXCEPT ![self] = "Done"]
                                      /\ UNCHANGED << obj, openUploads >>
                                 ELSE /\ IF CreateGuard = "ifnonematch" /\ obj[Enc].kind # "absent"
                                            THEN /\ openUploads' = openUploads \ {self}
                                                 /\ pc' = [pc EXCEPT ![self] = "migHeadEnc"]
                                                 /\ obj' = obj
                                            ELSE /\ openUploads' = openUploads \ {self}
                                                 /\ obj' = [obj EXCEPT ![Enc] = [kind |-> srcKind[self],
                                                                                 mid  |-> IF srcKind[self] = "multi" THEN self ELSE NoMid,
                                                                                 dek  |-> srcDek[self]]]
                                                 /\ pc' = [pc EXCEPT ![self] = "migDelete"]
                                      /\ UNCHANGED << srcDek, srcMid, srcKind >>
                        \/ /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                           /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                           /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                           /\ pc' = [pc EXCEPT ![self] = "Done"]
                           /\ UNCHANGED <<obj, openUploads>>
                     /\ UNCHANGED << manifests, latest, cleanEnd, upObserved, 
                                     delObserved, seen, current >>

migDelete(self) == /\ pc[self] = "migDelete"
                   /\ \/ /\ IF DeleteGuard = "ifmatch"
                               /\ (obj[Plain].kind = "absent" \/ obj[Plain].dek # srcDek[self])
                               THEN /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                                    /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                                    /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                                    /\ pc' = [pc EXCEPT ![self] = "migHeadPlain"]
                                    /\ obj' = obj
                               ELSE /\ obj' = [obj EXCEPT ![Plain] = Absent]
                                    /\ pc' = [pc EXCEPT ![self] = "migManifestDel"]
                                    /\ UNCHANGED << srcDek, srcMid, srcKind >>
                      \/ /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                         /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                         /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                         /\ pc' = [pc EXCEPT ![self] = "Done"]
                         /\ obj' = obj
                   /\ UNCHANGED << manifests, openUploads, latest, cleanEnd, 
                                   upObserved, delObserved, seen, current >>

migManifestDel(self) == /\ pc[self] = "migManifestDel"
                        /\ \/ /\ IF srcMid[self] # NoMid
                                    THEN /\ manifests' = [manifests EXCEPT ![Plain] = manifests[Plain] \ {srcMid[self]}]
                                    ELSE /\ TRUE
                                         /\ UNCHANGED manifests
                           \/ /\ TRUE
                              /\ UNCHANGED manifests
                        /\ cleanEnd' = [cleanEnd EXCEPT ![self] = TRUE]
                        /\ srcDek' = [srcDek EXCEPT ![self] = NoDek]
                        /\ srcMid' = [srcMid EXCEPT ![self] = NoMid]
                        /\ srcKind' = [srcKind EXCEPT ![self] = "absent"]
                        /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << obj, openUploads, latest, upObserved, 
                                        delObserved, seen, current >>

Mig(self) == migHeadPlain(self) \/ migHeadEnc(self) \/ migCreate(self)
                \/ migCopy(self) \/ migManifest(self) \/ migComplete(self)
                \/ migDelete(self) \/ migManifestDel(self)

putWrite == /\ pc["put"] = "putWrite"
            /\ \/ /\ ClientWrites
                  /\ obj' = [obj EXCEPT ![Enc] = [kind |-> "single", mid |-> NoMid, dek |-> PutDek]]
                  /\ latest' = PutDek
               \/ /\ TRUE
                  /\ UNCHANGED <<obj, latest>>
            /\ pc' = [pc EXCEPT !["put"] = "Done"]
            /\ UNCHANGED << manifests, openUploads, cleanEnd, srcDek, srcMid, 
                            srcKind, upObserved, delObserved, seen, current >>

Put == putWrite

upCreate == /\ pc[UpId] = "upCreate"
            /\ \/ /\ ClientWrites
                  /\ openUploads' = (openUploads \cup {UpId})
                  /\ pc' = [pc EXCEPT ![UpId] = "upHead"]
               \/ /\ pc' = [pc EXCEPT ![UpId] = "Done"]
                  /\ UNCHANGED openUploads
            /\ UNCHANGED << obj, manifests, latest, cleanEnd, srcDek, srcMid, 
                            srcKind, upObserved, delObserved, seen, current >>

upHead == /\ pc[UpId] = "upHead"
          /\ \/ /\ upObserved' = MidOf(Enc)
                /\ pc' = [pc EXCEPT ![UpId] = "upManifest"]
             \/ /\ pc' = [pc EXCEPT ![UpId] = "Done"]
                /\ UNCHANGED upObserved
          /\ UNCHANGED << obj, manifests, openUploads, latest, cleanEnd, 
                          srcDek, srcMid, srcKind, delObserved, seen, current >>

upManifest == /\ pc[UpId] = "upManifest"
              /\ \/ /\ manifests' = [manifests EXCEPT ![Enc] = manifests[Enc] \cup {UpId}]
                    /\ pc' = [pc EXCEPT ![UpId] = "upComplete"]
                    /\ UNCHANGED upObserved
                 \/ /\ upObserved' = NoMid
                    /\ pc' = [pc EXCEPT ![UpId] = "Done"]
                    /\ UNCHANGED manifests
              /\ UNCHANGED << obj, openUploads, latest, cleanEnd, srcDek, 
                              srcMid, srcKind, delObserved, seen, current >>

upComplete == /\ pc[UpId] = "upComplete"
              /\ \/ /\ IF UpId \notin openUploads
                          THEN /\ upObserved' = NoMid
                               /\ pc' = [pc EXCEPT ![UpId] = "Done"]
                               /\ UNCHANGED << obj, openUploads, latest >>
                          ELSE /\ openUploads' = openUploads \ {UpId}
                               /\ obj' = [obj EXCEPT ![Enc] = [kind |-> "multi", mid |-> UpId, dek |-> UpId]]
                               /\ latest' = UpId
                               /\ pc' = [pc EXCEPT ![UpId] = "upCleanup"]
                               /\ UNCHANGED upObserved
                 \/ /\ upObserved' = NoMid
                    /\ pc' = [pc EXCEPT ![UpId] = "Done"]
                    /\ UNCHANGED <<obj, openUploads, latest>>
              /\ UNCHANGED << manifests, cleanEnd, srcDek, srcMid, srcKind, 
                              delObserved, seen, current >>

upCleanup == /\ pc[UpId] = "upCleanup"
             /\ \/ /\ IF upObserved # NoMid
                         THEN /\ manifests' = [manifests EXCEPT ![Enc] = manifests[Enc] \ {upObserved}]
                         ELSE /\ TRUE
                              /\ UNCHANGED manifests
                \/ /\ TRUE
                   /\ UNCHANGED manifests
             /\ upObserved' = NoMid
             /\ pc' = [pc EXCEPT ![UpId] = "Done"]
             /\ UNCHANGED << obj, openUploads, latest, cleanEnd, srcDek, 
                             srcMid, srcKind, delObserved, seen, current >>

Up == upCreate \/ upHead \/ upManifest \/ upComplete \/ upCleanup

delHead == /\ pc["del"] = "delHead"
           /\ \/ /\ ClientDeletes
                 /\ delObserved' = MidOf(Enc)
                 /\ pc' = [pc EXCEPT !["del"] = "delRemove"]
              \/ /\ pc' = [pc EXCEPT !["del"] = "Done"]
                 /\ UNCHANGED delObserved
           /\ UNCHANGED << obj, manifests, openUploads, latest, cleanEnd, 
                           srcDek, srcMid, srcKind, upObserved, seen, current >>

delRemove == /\ pc["del"] = "delRemove"
             /\ \/ /\ obj' = [obj EXCEPT ![Enc] = Absent]
                   /\ latest' = Deleted
                   /\ pc' = [pc EXCEPT !["del"] = "delManifest"]
                   /\ UNCHANGED delObserved
                \/ /\ delObserved' = NoMid
                   /\ pc' = [pc EXCEPT !["del"] = "Done"]
                   /\ UNCHANGED <<obj, latest>>
             /\ UNCHANGED << manifests, openUploads, cleanEnd, srcDek, srcMid, 
                             srcKind, upObserved, seen, current >>

delManifest == /\ pc["del"] = "delManifest"
               /\ \/ /\ IF delObserved # NoMid
                           THEN /\ manifests' = [manifests EXCEPT ![Enc] = manifests[Enc] \ {delObserved}]
                           ELSE /\ TRUE
                                /\ UNCHANGED manifests
                  \/ /\ TRUE
                     /\ UNCHANGED manifests
               /\ delObserved' = NoMid
               /\ pc' = [pc EXCEPT !["del"] = "Done"]
               /\ UNCHANGED << obj, openUploads, latest, cleanEnd, srcDek, 
                               srcMid, srcKind, upObserved, seen, current >>

Del == delHead \/ delRemove \/ delManifest

staleWrite == /\ pc["stale"] = "staleWrite"
              /\ \/ /\ StaleWriter
                    /\ obj' = [obj EXCEPT ![Plain] = [kind |-> "single", mid |-> NoMid, dek |-> StaleDek]]
                    /\ latest' = StaleDek
                 \/ /\ TRUE
                    /\ UNCHANGED <<obj, latest>>
              /\ pc' = [pc EXCEPT !["stale"] = "Done"]
              /\ UNCHANGED << manifests, openUploads, cleanEnd, srcDek, srcMid, 
                              srcKind, upObserved, delObserved, seen, current >>

Stale == staleWrite

lifeAbort == /\ pc["lifecycle"] = "lifeAbort"
             /\ \E u \in openUploads:
                  openUploads' = openUploads \ {u}
             /\ pc' = [pc EXCEPT !["lifecycle"] = "lifeAbort"]
             /\ UNCHANGED << obj, manifests, latest, cleanEnd, srcDek, srcMid, 
                             srcKind, upObserved, delObserved, seen, current >>

Life == lifeAbort

gcList(self) == /\ pc[self] = "gcList"
                /\ \/ /\ seen' = [seen EXCEPT ![self] = manifests[GcKey(self)]]
                      /\ pc' = [pc EXCEPT ![self] = "gcUploads"]
                   \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                      /\ seen' = seen
                /\ UNCHANGED << obj, manifests, openUploads, latest, cleanEnd, 
                                srcDek, srcMid, srcKind, upObserved, 
                                delObserved, current >>

gcUploads(self) == /\ pc[self] = "gcUploads"
                   /\ \/ /\ IF UploadsAt(GcKey(self)) # {}
                               THEN /\ seen' = [seen EXCEPT ![self] = {}]
                                    /\ pc' = [pc EXCEPT ![self] = "Done"]
                               ELSE /\ pc' = [pc EXCEPT ![self] = "gcHead"]
                                    /\ seen' = seen
                      \/ /\ seen' = [seen EXCEPT ![self] = {}]
                         /\ pc' = [pc EXCEPT ![self] = "Done"]
                   /\ UNCHANGED << obj, manifests, openUploads, latest, 
                                   cleanEnd, srcDek, srcMid, srcKind, 
                                   upObserved, delObserved, current >>

gcHead(self) == /\ pc[self] = "gcHead"
                /\ \/ /\ current' = [current EXCEPT ![self] = MidOf(GcKey(self))]
                      /\ pc' = [pc EXCEPT ![self] = "gcDelete"]
                      /\ seen' = seen
                   \/ /\ seen' = [seen EXCEPT ![self] = {}]
                      /\ pc' = [pc EXCEPT ![self] = "Done"]
                      /\ UNCHANGED current
                /\ UNCHANGED << obj, manifests, openUploads, latest, cleanEnd, 
                                srcDek, srcMid, srcKind, upObserved, 
                                delObserved >>

gcDelete(self) == /\ pc[self] = "gcDelete"
                  /\ \/ /\ manifests' = [manifests EXCEPT ![GcKey(self)] = manifests[GcKey(self)] \ (seen[self] \ {current[self]})]
                     \/ /\ TRUE
                        /\ UNCHANGED manifests
                  /\ seen' = [seen EXCEPT ![self] = {}]
                  /\ current' = [current EXCEPT ![self] = NoMid]
                  /\ pc' = [pc EXCEPT ![self] = "Done"]
                  /\ UNCHANGED << obj, openUploads, latest, cleanEnd, srcDek, 
                                  srcMid, srcKind, upObserved, delObserved >>

Gc(self) == gcList(self) \/ gcUploads(self) \/ gcHead(self)
               \/ gcDelete(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == Put \/ Up \/ Del \/ Stale \/ Life
           \/ (\E self \in Runs: Mig(self))
           \/ (\E self \in {"gcPlain", "gcEnc"}: Gc(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

=============================================================================
