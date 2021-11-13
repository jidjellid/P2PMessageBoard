**Organisation**

Le dossier build contient la version compilée du programme.
Le dossier resources contient le fichier data.txt qui permet de sauvegarder les données du programme.
Le dossier src contient le code source du programme.
Le makefile permet de télécharger les librairies, et de compiler le programme.

**Execution**

La compilation et le téléchargement des librairies sont gérées par le makefile grâce à la commande 'make'.
Une fois compilé, le programme s'exécute grâce à la commande 'make run'.

Pour lancer le programme avec des arguments pour changer l'ip et le port de départ, la commande à exécuter sera 'make run arg1=... arg2=...'
Par exemple, pour passer "jch.irif.fr" sur le port 1212, la commande sera : make run arg1=jch.irif.fr arg2=1212

La commande "make debug" permets de lancer le programme avec Valgrind, il est aussi possible d'utiliser cette commande avec des arguments, cependant, il est important de noter que lors que le programme est lancé avec Valgrind, il est possible que certains paquets ne puissent être récupérées étant donné la lenteur du programme.

**Fonctionnalitée**

Depuis le terminal, pour afficher toutes les données ainsi que les voisins, il suffit d'appuyer sur la touche Entrée sans taper quoi que ce soit dans le terminal.
Appuyer sur la touche Entrée après avoir tapé un message dans le terminal remplacera le message du pair par la nouvelle entrée.
Taper "exit" dans le terminal permets de quitter le programme.