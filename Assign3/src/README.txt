Leontis Panagiotis AM: 2018030099


$ gcc --version
gcc (Ubuntu 9.3.0-17ubuntu1~20.04)

make clean
make all
make run
./acmonitor -m	,      ./acmonitor -i "file_0.txt"

Το πρόγραμμα λειτουργεί κανονικά. Στο test_aclog.c στα files 3-9 αφαιρώ to permission για read write και exec απο τον user. Στην συνέχεια προσπαθώ να
ανοίξω και να γράψω και τα 10 αρχεία αλλά για 7 από αυτά δεν έχω permition.
Στο file_logging γράφονται σωστά τα δεδομένα και ο malicious user και τα modifications εμφανίζονται σωστά.
Έγινε χρήση κώδικα από το stack overflow για να βρω το path του αρχείου μέσω του stream και να πάρω το όνομα του με την strtok() χωρίζοντας το
string ανα tokens("/").