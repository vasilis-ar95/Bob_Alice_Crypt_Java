import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;


//Κλάση αποθήκευσης των κλειδιών
public class StoreKeys_Class
{
    //Μέθοδος αποθήκευσης κλειδιών RSA
    public void store_rsa_keys(String public_key_file, String private_key_file, PublicKey publicKey, PrivateKey privateKey)
    {
        try
        {
            //KeyFactory είναι κλάση που μετατρέπει κλειδιά της κλάσης Key σε συγκεκριμένου τύπου ανάλογα τη χρήση που θέλουμε
            //Εδώ ορίζουμε ότι θέλουμε να είναι τύπου RSA
            KeyFactory fact = KeyFactory.getInstance("RSA");
            
            //Δημιουργία ενός δημόσιου κλειδιού της κλάσης RSAPublicKeySpec και αποθήκευση του modulus και εκθετικού του δημόσιου κλειδιού που έχει δημιουργηθεί
            RSAPublicKeySpec pub = fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
            //Κλήση της μεθόδου saveToFile που αποθηκεύει αυτά τα 2 στοιχεία στο αρχείο του δημόσιου κλειδιού
            saveToFile(public_key_file, pub.getModulus(), pub.getPublicExponent());
            //Δημιουργία ενός ιδιωτικού κλειδιού της κλάσης RSAPrivateKeySpec και αποθήκευση του modulus και εκθετικού του ιδιωτικού κλειδιού που έχει δημιουργηθεί
            RSAPrivateKeySpec priv = fact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            //Κλήση της μεθόδου saveToFile που αποθηκεύει αυτά τα 2 στοιχεία στο αρχείο του δημόσιου κλειδιού
            saveToFile(private_key_file, priv.getModulus(), priv.getPrivateExponent());
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException ex)
        {
            Logger.getLogger(StoreKeys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //Αποθήκευση του AES κλειδιού
    public void store_aes_keys(String aes_file_name, SecretKey aes_key)
    {
        ObjectOutputStream oout = null;//Δημιουργία ροής εξόδου
        try
        {
            oout = new ObjectOutputStream (new BufferedOutputStream(new FileOutputStream(aes_file_name)));
            oout.writeObject(aes_key);//Αποθήκευση του κλειδιού στο αρχείο
            oout.flush();
            oout.close();
        }
        catch (FileNotFoundException ex)
        {
            Logger.getLogger(StoreKeys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (IOException ex)
        {
            Logger.getLogger(StoreKeys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
   
    //Μέθοδος αποθήκευσης των κλειδιών του RSA
    public void saveToFile(String fileName, BigInteger mod, BigInteger exp)
    {
        ObjectOutputStream oout = null;//Δημιουργία ροής εξόδου
        try
        {
            oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
            //Αποθήκευση του κλειδιού στο αρχείο
            oout.writeObject(mod);
            oout.writeObject(exp);
            oout.flush();
            oout.close();
        }
        catch (IOException ex)
        {
            Logger.getLogger(StoreKeys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //Μέθοδος ανάγνωση κλειδιών
    public PublicKey readPublicKey(String file_name)
    {
        ObjectInputStream oin = null;
        KeyFactory fact = null;
        RSAPublicKeySpec keySpec = null;
        PublicKey public_key = null;
        try
        {
            oin = new ObjectInputStream(new FileInputStream(file_name));//Ροή ανάγνωσης αρχείων
            //Αποθήκευση του modulus και exponents σε 2 BigIntegers
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            //Δημιουργία ενός RSAPublicKeySpec αντικειμένου με τα παραπάνω στοιχεία
            keySpec = new RSAPublicKeySpec(m, e);
            //Μετατροπή σε RSA
            fact = KeyFactory.getInstance("RSA");
            //Δημιουργία του PublicKey αντικειμένου
            public_key = fact.generatePublic(keySpec);
        }
        catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException ex)
        {
            Logger.getLogger(StoreKeys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return public_key;
    }
}