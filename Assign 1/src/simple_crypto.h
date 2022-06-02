/**
 * Function for encrypting a text using OTP algorithm
 * @param plaintext text for encryption
 * @param key key
 * @return Prints encrypted message
 */
char* otp_encrypt(char plaintext[]);
/**
 * Function for decrypting a text using OTP algorithm
 * @param encrypted text for decryption
 * @return Prints encrypted message and returns it
 */
void otp_decrypt(char encrypted[]);
/**
 * Function for creating a random key based on given plaintext.Using /dev/random
 * Usage at OTP encryption 
 */
void createOtpKey(char plaintext[]);
/**
 * Function for printing encrypted text to user with OTP algorithm. Checks if character is 
 * a printable ASCII character and prints it. If not, hex form is printed
 * Usage at OTP encryption 
 */
void checkIfPrintable(char plaintext[]);
/**
 * Function for encrypting a text using CEASARS algorithm
 * @param plaintext text for encryption
 * @param key key
 * @return Prints encrypted message and returns it
 */
char* ceasars_encrypt(char plaintext[], int key);
/**
 * Function for decrypting a text using CEASARS algorithm
 * @param encrypted text for decryption
 * @param key same key used in encryption
 * @return Prints decrypted message
 */
void ceasars_decrypt(char encrypted[], int key);
/**
 * Function for encrypting a text using VIGENERES algorithm
 * @param plaintext text for encryption
 * @param key key
 * @return Prints encrypted message and returns it
 */
char* vigeneres_encrypt(char plaintext[], char key[]);
/**
 * Function for encrypting a text using VIGENERES algorithm
 * @param plaintext text for encryption
 * @param key key
 * @return Prints encrypted message
 */
void vigeneres_decrypt(char encrypted[], char key[]);

/**
 * Function for editing VIGENERES key when is smaller than plaintext  
 * Example: plaintext:ATTACKATDAWN  key: LEMON
 *                  Modified key=> LEMONLEMONLE
 * @param length Length of plaintext array for measuring
 * @param key Array of key for editing
 * @returns Key either the same or modified if was necessary
 */
char* modifyVigeneresKey(int textLength, char key[]);
