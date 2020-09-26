
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

//Κλάση κρυπτογράφησης του AES κλειδιού
public class Encapsulation_Class
{
    private SecretKey secretKey;
    
    //Δημιουργία του κλειδιού
    public SecretKey aes_key_generation()
    {
        try 
        {
            Security.addProvider(new BouncyCastleProvider());
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");//γεννήτρια στην οποία ορίζουμε τον αλγόριθμο για τον οποίο θέλουμε να παράξει κλειδί
            keyGen.init(256); // μέγεθος κλειδιού 256 bit
            secretKey = keyGen.generateKey(); //δημιουργία του κλειδιού
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Encapsulation_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Encapsulation_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return secretKey;
    }
    
    //Κρυπτογράφηση του AES
    public byte[] encrypt(PublicKey public_key, SecretKey secret_key)
    {
        byte []encrypted = null;
        try 
        {
            //Αντικείμενο της κλάσης Cipher
            //Ορίζουμε τον αλγόριθμο κρυπτογράφησης: RSA
            //PKCS1Padding --> Ορίζει τη μαθηματική προσέγγιση και τις ιδιότητες του RSA
            //None --> Αφού ο RSA δεν είναι block cipher, με τη βοήθεια της Bouncy Castle, μπορούμε να ορίσουμε ότι δε θα πάρει κανένα Block cipher mode of operation
            Cipher c = Cipher.getInstance("RSA/None/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, public_key);
            encrypted = c.doFinal(secret_key.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(Encapsulation_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return encrypted;
    }
    
    public SecretKey decrypt(PrivateKey private_key, byte [] encrypted)
    {
        SecretKey secret_key = null;
        try 
        {
            //Αντικείμενο της κλάσης Cipher
            //Ορίζουμε τον αλγόριθμο αποκρυπτογράφησης: RSA
            //PKCS1Padding --> Ορίζει τη μαθηματική προσέγγιση και τις ιδιότητες του RSA
            //None --> Αφού ο RSA δεν είναι block cipher, με τη βοήθεια της Bouncy Castle, μπορούμε να ορίσουμε ότι δε θα πάρει κανένα Block cipher mode of operation
            Cipher c = Cipher.getInstance("RSA/None/PKCS1Padding");
            c.init(Cipher.DECRYPT_MODE, private_key);
            c.doFinal(encrypted);
            secret_key = new SecretKeySpec(c.doFinal(encrypted), "AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Encapsulation_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return secret_key;
    }
}