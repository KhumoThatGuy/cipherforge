/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package cipherforge;

    import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

public class CipherForge {
    
    
     private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%&*()-_=+<>?";
    private static final Scanner scanner = new Scanner(System.in);
    private static final String AES_ALGO = "AES/CBC/PKCS5Padding";
    
    public static void main(String[] args){
    




   System.out.println(" ______  ________  _______ ___   ___ _______    ______             ");
System.out.println("/ _____||_________/      | |  | |  | |  ____|  |   _  \\     ");
System.out.println("| |        | |    |   || | |  |_|  | |  |___   |  |_)  |              ");
System.out.println("| |        | |    |  ____/ |   __  | |   ___|  |      /           ");
System.out.println("| |        | |    |  |     |  | |  | |  |      |     \\         ");
System.out.println("| |___   __| |__  |  |     |  | |  | |  |___   |   |\\ \\                  ");
System.out.println("\\_____| |_______| |__|     |__|_|__| |______|  |___| \\_\\        ");

   
       System.out.println("\n" +

"                                                                                \n" +
" [*] AES-256 + SHA-512 Encryption Engine | Secure. Fast. Untraceable.           \n" +
" [*] Author: Boipelo Mogami | IG: m.khumo_101                                   \n" +
"                             \n" +
"\n");

        System.out.println("Choose an option:");
        System.out.println("1. Generate Password");
        System.out.println("2. Encrypt Password (AES)");
        System.out.println("3. Decrypt Password (AES)");
        System.out.println("4. Hash Password (SHA-512)");
        System.out.print("Enter your choice (1-4): ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // flush newline

        switch (choice) {
            case 1 -> generatePasswordFlow();
            case 2 -> aesEncryptionFlow();
            case 3 -> aesDecryptionFlow();
            case 4 -> hashPasswordFlow();
            default -> System.out.println("Invalid choice.");
        }

        System.out.println("\n Thank you for using CipherForge!");
    }

    // ================== Password Generator ====================
    private static void generatePasswordFlow() {
        System.out.print("Enter password length: ");
        int length = scanner.nextInt();
        scanner.nextLine();

        boolean useUpper = getYesOrNo("Include uppercase letters? (y/n): ");
        boolean useLower = getYesOrNo("Include lowercase letters? (y/n): ");
        boolean useDigits = getYesOrNo("Include digits? (y/n): ");
        boolean useSymbols = getYesOrNo("Include symbols? (y/n): ");

        try {
            String password = generatePassword(length, useUpper, useLower, useDigits, useSymbols);
            System.out.println("\nGenerated Password: " + password);
        } catch (IllegalArgumentException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static String generatePassword(int length, boolean upper, boolean lower, boolean digits, boolean symbols) {
        StringBuilder pool = new StringBuilder();
        if (upper) pool.append(UPPERCASE);
        if (lower) pool.append(LOWERCASE);
        if (digits) pool.append(DIGITS);
        if (symbols) pool.append(SYMBOLS);

        if (pool.isEmpty()) throw new IllegalArgumentException("At least one character type must be selected.");

        SecureRandom rand = new SecureRandom();
        StringBuilder password = new StringBuilder();

        for (int i = 0; i < length; i++) {
            int index = rand.nextInt(pool.length());
            password.append(pool.charAt(index));
        }

        return password.toString();
    }

    // ================== AES Encryption ====================
    private static void aesEncryptionFlow() {
        System.out.print("Enter password to encrypt: ");
        String plainText = scanner.nextLine();

        System.out.print("Enter secret key (16/24/32 chars for AES-128/192/256): ");
        String key = scanner.nextLine();

        try {
            byte[] iv = generateIV();
            String ivHex = bytesToHex(iv);
            String encrypted = encryptAES(plainText, key, iv);

            System.out.println("\nEncrypted (AES): " + encrypted);
            System.out.println("IV (keep this for decryption): " + ivHex);
        } catch (Exception e) {
            System.out.println("Encryption error: " + e.getMessage());
        }
    }

    private static void aesDecryptionFlow() {
        System.out.print("Enter AES-encrypted text: ");
        String encryptedText = scanner.nextLine();

        System.out.print("Enter secret key used for encryption: ");
        String key = scanner.nextLine();

        System.out.print("Enter IV (hex format): ");
        String ivHex = scanner.nextLine();
        byte[] iv = hexToBytes(ivHex);

        try {
            String decrypted = decryptAES(encryptedText, key, iv);
            System.out.println("\nDecrypted text: " + decrypted);
        } catch (Exception e) {
            System.out.println("Decryption error: " + e.getMessage());
        }
    }

    private static String encryptAES(String plainText, String key, byte[] ivBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        SecretKey secretKey = new SecretKeySpec(normalizeKey(key), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptAES(String encryptedText, String key, byte[] ivBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        SecretKey secretKey = new SecretKeySpec(normalizeKey(key), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(decryptedBytes);
    }

    private static byte[] normalizeKey(String key) {
        // AES key must be 16, 24, or 32 bytes
        byte[] keyBytes = Arrays.copyOf(key.getBytes(), 32); // AES-256
        return keyBytes;
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[16]; // 128-bit IV for AES
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // ================== SHA-512 Hashing ====================
    private static void hashPasswordFlow() {
        System.out.print("Enter password to hash: ");
        String password = scanner.nextLine();

        try {
            String hashed = hashSHA512(password);
            System.out.println("\nSHA-512 Hash:\n" + hashed);
        } catch (Exception e) {
            System.out.println("Hashing failed: " + e.getMessage());
        }
    }

    private static String hashSHA512(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] hashBytes = md.digest(input.getBytes());

        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    // ================== Utility ====================
    private static boolean getYesOrNo(String message) {
        System.out.print(message);
        String input = scanner.nextLine().trim().toLowerCase();
        return input.startsWith("y");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] result = new byte[len / 2];

        for (int i = 0; i < len; i += 2)
            result[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                  + Character.digit(hex.charAt(i+1), 16));

        return result;
    }


    
    }

