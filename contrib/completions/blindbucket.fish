# fish completion for blindbucket.
#
# Copy it to ~/.config/fish/completions/blindbucket.fish. Homebrew's
# vendor_completions.d directory is read as well.
#
# Hand-written, so a new flag does not appear here by itself. The test in
# cmd/blindbucket/completions_test.go fails when the flags offered here and
# the ones `blindbucket <command> -h` lists differ.

# The command on the line, with the subcommand for keys, tenants and audit:
# "rotate", "keys list". A subcommand has to come right after its command,
# which is what the CLI requires too.
function __blindbucket_command
    set -l words (commandline -opc)
    set -q words[2]; or return
    switch $words[2]
        case keys tenants audit
            if set -q words[3]
                echo "$words[2] $words[3]"
            else
                echo $words[2]
            end
        case '*'
            echo $words[2]
    end
end

function __blindbucket_using
    set -l command (__blindbucket_command)
    test "$command" = "$argv"
end

function __blindbucket_needs_command
    test (count (commandline -opc)) -eq 1
end

complete -c blindbucket -f

# Commands.
set -l without_command __blindbucket_needs_command
complete -c blindbucket -n "$without_command" -a init -d 'write a configuration, a keyring and client credentials to start from'
complete -c blindbucket -n "$without_command" -a doctor -d 'check a configuration, its keyring and the provider, and name what to fix'
complete -c blindbucket -n "$without_command" -a serve -d 'run the S3 gateway'
complete -c blindbucket -n "$without_command" -a keygen -d 'create a keyring, or add a key to an existing one'
complete -c blindbucket -n "$without_command" -a keys -d 'list the keys in a keyring, or retire one'
complete -c blindbucket -n "$without_command" -a reseal -d 'seal a keyring under another passphrase, Vault or KMS'
complete -c blindbucket -n "$without_command" -a tenants -d 'add tenants, give them buckets, activate and list them'
complete -c blindbucket -n "$without_command" -a gc -d 'remove orphaned multipart manifests and tag sidecars'
complete -c blindbucket -n "$without_command" -a rotate -d 're-wrap data keys under a new KEK'
complete -c blindbucket -n "$without_command" -a migrate-names -d 'move objects stored in clear to their encrypted names'
complete -c blindbucket -n "$without_command" -a encrypt-existing -d 'encrypt the objects a bucket held before the gateway, in place'
complete -c blindbucket -n "$without_command" -a probe -d "measure the provider's conditional writes"
complete -c blindbucket -n "$without_command" -a scrub -d 'verify every stored object without waiting for a read'
complete -c blindbucket -n "$without_command" -a audit -d 'verify the audit log, or print the key that verifies it'
complete -c blindbucket -n "$without_command" -a encrypt -d 'encrypt a stream into a blindbucket file'
complete -c blindbucket -n "$without_command" -a decrypt -d 'decrypt a blindbucket file'
complete -c blindbucket -n "$without_command" -a inspect -d "show a file's format details without decrypting it"
complete -c blindbucket -n "$without_command" -a version -d 'print the version and exit'
complete -c blindbucket -n "$without_command" -a help -d 'list the commands'

# Subcommands.
complete -c blindbucket -n '__blindbucket_using keys' -a list -d 'show the key-encryption keys in a keyring, and how old they are'
complete -c blindbucket -n '__blindbucket_using keys' -a remove -d 'retire a key that nothing references any more'
complete -c blindbucket -n '__blindbucket_using tenants' -a create -d 'add a tenant, inactive, with its keys, its lock and its buckets'
complete -c blindbucket -n '__blindbucket_using tenants' -a assign -d 'give a tenant more buckets, for good'
complete -c blindbucket -n '__blindbucket_using tenants' -a activate -d "write a tenant's buckets under its own keys from now on"
complete -c blindbucket -n '__blindbucket_using tenants' -a list -d 'show the tenants, their buckets, keys and locks'
complete -c blindbucket -n '__blindbucket_using audit' -a verify -d "check a log's hash chain and checkpoint signatures"
complete -c blindbucket -n '__blindbucket_using audit' -a pubkey -d 'print the public key a verifier needs'

# init
set -l c '__blindbucket_using init'
complete -c blindbucket -n $c -l bucket -x -d 'the bucket the generated client may use'
complete -c blindbucket -n $c -l credential-source -x -a 'env profile web_identity container imds chain' -d 'take AWS credentials from the platform instead of keys'
complete -c blindbucket -n $c -l dir -x -a '(__fish_complete_directories)' -d 'directory to write the three files into'
complete -c blindbucket -n $c -l encrypt-names -d 'encrypt object names; only for a bucket with no objects yet'
complete -c blindbucket -n $c -l endpoint -x -d "the provider's S3 endpoint"
complete -c blindbucket -n $c -l keys-provider -x -a 'file vault awskms' -d 'what seals the keyring'
complete -c blindbucket -n $c -l kid -x -d "id of the keyring's first key-encryption key"
complete -c blindbucket -n $c -l kms-endpoint -x -d 'override for an AWS-compatible KMS endpoint'
complete -c blindbucket -n $c -l kms-key-id -x -d 'KMS key id, alias or ARN'
complete -c blindbucket -n $c -l kms-region -x -d 'KMS region'
complete -c blindbucket -n $c -l non-interactive -d 'never ask; a missing answer is an error'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -l path-style -d 'name the bucket in the path rather than the host name'
complete -c blindbucket -n $c -l region -x -d "the provider's region"
complete -c blindbucket -n $c -l vault-address -x -d 'Vault or OpenBao address'
complete -c blindbucket -n $c -l vault-key-name -x -d 'the Transit key that seals the keyring'
complete -c blindbucket -n $c -l vault-mount -x -d 'where the Transit engine is mounted'

# doctor
set c '__blindbucket_using doctor'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l json -d 'emit the checks as JSON'
complete -c blindbucket -n $c -l no-write -d 'skip the one check that writes to the provider'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'

# serve
set c '__blindbucket_using serve'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -s v -d 'log at debug level'

# keygen
set c '__blindbucket_using keygen'
complete -c blindbucket -n $c -l activate -d 'with --add, make the new key the active one'
complete -c blindbucket -n $c -l add -d 'add a key to an existing keyring instead of creating one'
complete -c blindbucket -n $c -l add-audit-key -d 'add an audit-log signing key to an existing keyring'
complete -c blindbucket -n $c -l add-freshness-key -d 'add a rollback-index key to an existing keyring'
complete -c blindbucket -n $c -l add-name-key -d 'add an object-name key to an existing keyring'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file naming the root-key provider'
complete -c blindbucket -n $c -l kid -x -d 'id of the key to create'
complete -c blindbucket -n $c -l out -r -F -d 'keyring file to write'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'

# reseal
set c '__blindbucket_using reseal'
complete -c blindbucket -n $c -l config -r -F -d 'configuration naming the source the keyring is sealed with now'
complete -c blindbucket -n $c -l dry-run -d 'seal and unseal with the new source, write nothing'
complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file to reseal'
complete -c blindbucket -n $c -l new-passphrase-file -r -F -d 'read the new passphrase from this file'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -l tenant -r -f -d 'reseal this tenant instead of the deployment'
complete -c blindbucket -n $c -l to-config -r -F -d 'configuration naming the source to seal it with'

# gc
set c '__blindbucket_using gc'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l dry-run -d 'report what would be deleted, delete nothing'
complete -c blindbucket -n $c -l json -d 'emit the summary as JSON'
complete -c blindbucket -n $c -l min-age -x -d 'leave manifests younger than this alone'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -s v -d 'log at debug level'

# rotate
set c '__blindbucket_using rotate'
complete -c blindbucket -n $c -l allow-unconditional -d 'write without If-Match; see the warning it prints'
complete -c blindbucket -n $c -l concurrency -x -d 'objects to rotate at once'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l dry-run -d 'report what would be rotated, change nothing'
complete -c blindbucket -n $c -l json -d 'emit the summary as JSON'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -l to-kid -x -d 'key id to wrap under; defaults to the active key'
complete -c blindbucket -n $c -s v -d 'log at debug level'

# migrate-names
set c '__blindbucket_using migrate-names'
complete -c blindbucket -n $c -l allow-unconditional -d 'publish without If-None-Match; see the warning it prints'
complete -c blindbucket -n $c -l concurrency -x -d 'objects to migrate at once'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l dry-run -d 'report what would be migrated, change nothing'
complete -c blindbucket -n $c -l json -d 'emit the summary as JSON'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -s v -d 'log at debug level'

# encrypt-existing
set c '__blindbucket_using encrypt-existing'
complete -c blindbucket -n $c -l allow-unconditional -d 'write without the condition that keeps a client\'s write'
complete -c blindbucket -n $c -l concurrency -x -d 'objects to encrypt at once'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l dry-run -d 'report what would be encrypted, change nothing'
complete -c blindbucket -n $c -l json -d 'emit the summary as JSON'
complete -c blindbucket -n $c -l keep-versions -d 'run on a versioned bucket, removing old versions yourself'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -s v -d 'log at debug level'

# probe
set c '__blindbucket_using probe'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l json -d 'emit the result as JSON'

# scrub
set c '__blindbucket_using scrub'
complete -c blindbucket -n $c -l concurrency -x -d 'objects to verify at once'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file'
complete -c blindbucket -n $c -l json -d 'emit the result as JSON'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -s v -d 'log at debug level, one line per object'

# encrypt and decrypt
set c '__blindbucket_using encrypt'
complete -c blindbucket -n $c -l chunk-size-log2 -x -d 'chunk size as a power of two'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file naming the root-key provider'
complete -c blindbucket -n $c -s i -r -F -d 'input file, or - for stdin'
complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file'
complete -c blindbucket -n $c -s o -r -F -d 'output file, or - for stdout'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
set c '__blindbucket_using decrypt'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file naming the root-key provider'
complete -c blindbucket -n $c -s i -r -F -d 'input file, or - for stdin'
complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file'
complete -c blindbucket -n $c -s o -r -F -d 'output file, or - for stdout'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'

# inspect: the file it reads is the one positional argument.
set c '__blindbucket_using inspect'
complete -c blindbucket -n $c -F
complete -c blindbucket -n $c -l json -d 'emit the fields as JSON'

# keys list and keys remove
set c '__blindbucket_using keys list'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file naming the root-key provider'
complete -c blindbucket -n $c -l json -d 'emit the key list as JSON'
complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
set c '__blindbucket_using keys remove'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file naming the root-key provider'
complete -c blindbucket -n $c -l force -d 'confirm that no object is wrapped under the key any more'
complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'

# tenants create, assign, activate and list
for sub in create assign activate list
    set c "__blindbucket_using tenants $sub"
    complete -c blindbucket -n $c -l config -r -F -d "configuration naming the root-key provider, and each tenant's lock"
    complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file'
    complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
end
complete -c blindbucket -n '__blindbucket_using tenants create' -l deployment-lock -d "seal the tenant under the deployment's lock"
complete -c blindbucket -n '__blindbucket_using tenants create' -l kid -x -d "id of the tenant's first key"
complete -c blindbucket -n '__blindbucket_using tenants activate' -l kid -x -d 'the key to activate'
complete -c blindbucket -n '__blindbucket_using tenants list' -l json -d 'emit the tenant list as JSON'

# audit verify and audit pubkey
set c '__blindbucket_using audit verify'
complete -c blindbucket -n $c -F
complete -c blindbucket -n $c -l config -r -F -d 'configuration file naming the root-key provider'
complete -c blindbucket -n $c -l expect -x -d 'require the chain to reach at least this checkpoint, as seq:hash'
complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file: verifies, and decrypts the object names'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
complete -c blindbucket -n $c -l print -d 'print every entry'
complete -c blindbucket -n $c -l public-key -r -F -d 'base64 Ed25519 public key, or a file containing one'
set c '__blindbucket_using audit pubkey'
complete -c blindbucket -n $c -l config -r -F -d 'configuration file naming the root-key provider'
complete -c blindbucket -n $c -l keyring -r -F -d 'keyring file'
complete -c blindbucket -n $c -l open -d 'open the keyring and derive the key, instead of reading the recorded one'
complete -c blindbucket -n $c -l passphrase-file -r -F -d 'read the keyring passphrase from this file'
