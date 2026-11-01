#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "merkle_tree.h"

#define MAX_LINE_LEN 256

void sanitize_line(char *line) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
    if (len >= 2 && line[0] == '"' && line[len - 1] == '"') {
        memmove(line, line + 1, len - 2);
        line[len - 2] = '\0';
    }
}

int main(void) {
    const char *target_name = "Ursu Mihai";

    FILE *file = fopen("students_2026.txt", "r");
    if (!file) {
        perror("Eroare la deschidere");
        return 1;
    }

    MerkleTree *tree = create_merkle_tree();
    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), file)) {
        sanitize_line(line);
        if (strlen(line) > 0) {
            add_element(tree, line);
        }
    }
    fclose(file);

    const unsigned char *root_hash = get_root_hash(tree);
    char *root_hex = hash_to_string(root_hash);
    printf("Merkle Root: %s\n\n", root_hex);

    printf("Generare dovada pentru: \"%s\"\n", target_name);
    MerkleProof *proof = generate_proof(tree, target_name);

    if (!proof) {
        printf("Eroare: Numele \"%s\" nu a fost gasit\n", target_name);
        free(root_hex);
        free_merkle_tree(tree);
        return 1;
    }

    bool valid = verify_proof(root_hash, target_name, proof);
    printf("Verificare dovada: %s\n\n", valid ? "VALIDA" : "INVALIDA");

    int count = get_proof_count(proof);
    printf("Dovada (%d siblings)\n", count);
    for (int i = 0; i < count; i++) {
        const unsigned char *sib = get_proof_sibling(proof, i);
        char *sib_hex = hash_to_string(sib);
        printf("[%d] Hash frate: %s\n", i, sib_hex);
        free(sib_hex);
    }

    free(root_hex);
    free_merkle_proof(proof);
    free_merkle_tree(tree);

    return 0;
}