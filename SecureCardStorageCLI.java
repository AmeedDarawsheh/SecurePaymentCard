import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.io.File;

public class SecureCardStorageCLI {
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 128; // bits
    private static final String DATA_FILE = "card.dat";

    // Generate AES key from password
    public static SecretKey generateKeyFromPassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Generate random salt
    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // Generate random IV (Initialization Vector)
    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Encrypt data using AES/CBC/PKCS5Padding
    public static String encrypt(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt data using AES/CBC/PKCS5Padding
    public static String decrypt(String encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, "UTF-8");
    }

    // Encrypt the salt and IV using AES before storing them
    public static String encryptSaltAndIv(byte[] salt, byte[] iv, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
        
        byte[] saltAndIvData = new byte[salt.length + iv.length];
        System.arraycopy(salt, 0, saltAndIvData, 0, salt.length);
        System.arraycopy(iv, 0, saltAndIvData, salt.length, iv.length);
        
        byte[] encryptedSaltAndIv = cipher.doFinal(saltAndIvData);
        return Base64.getEncoder().encodeToString(encryptedSaltAndIv);
    }

    // Save encrypted data (salt, IV, encrypted data) to file
    public static void storeData(byte[] salt, byte[] iv, String encryptedData, SecretKey key) throws Exception {
        File file = new File(DATA_FILE);
        if (file.exists()) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("The file already exists. Do you want to overwrite it? (yes/no): ");
            String choice = scanner.nextLine();
            if (choice.equalsIgnoreCase("no")) {
                return; // Don't overwrite the file
            }
        }

        String encryptedSaltAndIv = encryptSaltAndIv(salt, iv, key);
        String content = encryptedSaltAndIv + "\n" + encryptedData;
        Files.write(Paths.get(DATA_FILE), content.getBytes("UTF-8"));
        System.out.println("Data saved to " + DATA_FILE);
    }

    // Read encrypted data from file
    public static String[] loadData() throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(DATA_FILE));
        if (lines.size() < 2) {
            throw new Exception("Incomplete file data.");
        }
        return new String[]{lines.get(0), lines.get(1)};
    }

    // Main method for CLI
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Welcome to the Secure Card Storage CLI");

        // Encrypt and store data
        System.out.print("Enter card number to encrypt: ");
        String cardNumber = scanner.nextLine().trim();

        System.out.print("Enter password: ");
        String password = scanner.nextLine().trim();

        if (cardNumber.isEmpty() || password.isEmpty()) {
            System.out.println("Card number and password cannot be empty!");
            return;
        }

        try {
            byte[] salt = generateSalt();
            byte[] iv = generateIV();
            SecretKey key = generateKeyFromPassword(password.toCharArray(), salt);
            String encryptedCard = encrypt(cardNumber, key, iv);

            storeData(salt, iv, encryptedCard, key);
            System.out.println("Encrypted card number: " + encryptedCard);

        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Error encrypting and saving data.");
        }

        // Decrypt and retrieve data
        System.out.print("Enter password to decrypt data: ");
        password = scanner.nextLine().trim();

        if (password.isEmpty()) {
            System.out.println("Password cannot be empty!");
            return;
        }

        try {
            String[] data = loadData();
            String encryptedSaltAndIv = data[0];
            String encryptedCard = data[1];

            byte[] saltAndIvData = Base64.getDecoder().decode(encryptedSaltAndIv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKey key = generateKeyFromPassword(password.toCharArray(), saltAndIvData);
            byte[] decryptedSaltAndIvData = cipher.doFinal(saltAndIvData);
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            System.arraycopy(decryptedSaltAndIvData, 0, salt, 0, salt.length);
            System.arraycopy(decryptedSaltAndIvData, salt.length, iv, 0, iv.length);

            String decryptedCard = decrypt(encryptedCard, key, iv);
            System.out.println("Decrypted card number: " + decryptedCard);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Error decrypting data.");
        }

        scanner.close();
    }
}
