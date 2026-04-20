// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = (type == OBJ_BLOB) ? "blob" :
                           (type == OBJ_TREE) ? "tree" : "commit";

    // build header: "blob 16\0" etc
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // combine header + data into one buffer
    size_t full_len = header_len + len;
    uint8_t *full = malloc(full_len);
    if (!full) return -1;
    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    // hash the whole thing
    compute_hash(full, full_len, id_out);

    // already stored, nothing to do
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // make the shard directory
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);

    // write to a temp file first
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_XXXXXX", shard_dir);
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }
    write(fd, full, full_len);
    fsync(fd);
    close(fd);

    // move temp file to final location atomically
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));
    rename(tmp_path, final_path);

    // fsync the directory so the rename is durable
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full);
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    // read entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    size_t full_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *full = malloc(full_len);
    if (!full) {
        fclose(f);
        return -1;
    }
    fread(full, 1, full_len, f);
    fclose(f);

    // verify the hash matches what was requested
    ObjectID computed;
    compute_hash(full, full_len, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(full);
        return -1;
    }

    // find the null byte separating header from data
    uint8_t *null_pos = memchr(full, '\0', full_len);
    if (!null_pos) {
        free(full);
        return -1;
    }

    // parse the type from the header
    char *header = (char *)full;
    if (strncmp(header, "blob", 4) == 0)
        *type_out = OBJ_BLOB;
    else if (strncmp(header, "tree", 4) == 0)
        *type_out = OBJ_TREE;
    else if (strncmp(header, "commit", 6) == 0)
        *type_out = OBJ_COMMIT;
    else {
        free(full);
        return -1;
    }

    // copy out the data portion after the null byte
    size_t data_offset = null_pos - full + 1;
    *len_out = full_len - data_offset;
    *data_out = malloc(*len_out);
    memcpy(*data_out, full + data_offset, *len_out);

    free(full);
    return 0;
}
