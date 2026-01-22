#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    const char *fichiers[] = {
        "calckeyb.s", 
        "calculator.s", 
        "simple_add.s", 
        "testfp.s", 
        "tty.s"
    };
    int nb_fichiers = 5;

    printf("Début de la transformation (avec nettoyage de .addrsig)...\n\n");

    for (int i = 0; i < nb_fichiers; i++) {
        char nom_base[100];
        char cmd_nettoyage[512];
        char cmd_assemblage[512];
        char cmd_binaire[512];

        // Extraction du nom de base
        strncpy(nom_base, fichiers[i], strlen(fichiers[i]) - 2);
        nom_base[strlen(fichiers[i]) - 2] = '\0';

        printf("[%d/%d] Traitement de : %s\n", i + 1, nb_fichiers, fichiers[i]);

        // 1. Nettoyage : On crée une copie temporaire sans les directives .addrsig
        // La commande 'sed' supprime toutes les lignes contenant .addrsig
        sprintf(cmd_nettoyage, "sed '/.addrsig/d' %s > %s.tmp.s", fichiers[i], nom_base);
        if (system(cmd_nettoyage) != 0) {
            fprintf(stderr, "Erreur lors du nettoyage de %s\n", fichiers[i]);
            continue;
        }

        // 2. Assemblage à partir du fichier temporaire nettoyé
        sprintf(cmd_assemblage, "arm-none-eabi-as -mcpu=cortex-m0 -o %s.o %s.tmp.s", nom_base, nom_base);
        if (system(cmd_assemblage) != 0) {
            fprintf(stderr, "Erreur lors de l'assemblage de %s\n", fichiers[i]);
            remove(strcat(nom_base, ".tmp.s")); // Nettoyage si échec
            continue;
        }

        // 3. Conversion en binaire brut (.bin)
        char nom_obj[120], nom_bin[120], nom_tmp[120];
        sprintf(nom_obj, "%s.o", nom_base);
        sprintf(nom_bin, "%s.bin", nom_base);
        sprintf(nom_tmp, "%s.tmp.s", nom_base);

        sprintf(cmd_binaire, "arm-none-eabi-objcopy -O binary %s %s", nom_obj, nom_bin);
        if (system(cmd_binaire) == 0) {
            printf("   -> Succès : %s généré.\n", nom_bin);
        }

        // Nettoyage des fichiers intermédiaires
        remove(nom_obj);
        remove(nom_tmp);
    }

    printf("\nOpération terminée.\n");
    return 0;
}