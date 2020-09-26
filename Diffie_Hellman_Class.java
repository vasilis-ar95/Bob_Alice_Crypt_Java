import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;


public class Diffie_Hellman_Class
{
    private KeyPairGenerator keyGen;
    private int keySize = 3072;
    private SecureRandom random = new SecureRandom();
    private KeyAgreement aliceKeyAgree;
    private KeyAgreement bobKeyAgree;
    private KeyPair bobPair;
    private KeyPair alicePair;
    private BigInteger g = new BigInteger(keySize, random);
    private BigInteger p = new BigInteger(keySize, random);
    
    //Δημιουργία του κοινού αριθμού των 2 χρηστών
    public DHParameterSpec create_same_number()
    {
        DHParameterSpec dhParams = null;
        try 
        {
            Security.addProvider(new BouncyCastleProvider());
            //Δημιουργούμε ένα ζευγάρι με παραμέτρους p, q
            //Το μέγεθος το έχουμε ορίσει στις δηλώσεις μεταβλητών σε 3072 bits
            dhParams = new DHParameterSpec(p, g);
            keyGen = KeyPairGenerator.getInstance("DH", "BC");
            keyGen.initialize(dhParams, random);
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex)
        {
            Logger.getLogger(Diffie_Hellman_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return dhParams;
    }
    
    //KeyAgreement του Bob
    public KeyAgreement create_bob_key()
    {
        try 
        {
            //Δημιουργία του κλειδιού του Bob, ορίζουμε τον αλγόριθμο και τον πάροχο
            bobKeyAgree = KeyAgreement.getInstance("DH", "BC");
            bobPair = keyGen.generateKeyPair();
            bobKeyAgree.init(bobPair.getPrivate());
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex)
        {
            Logger.getLogger(Diffie_Hellman_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return bobKeyAgree;
    }
    
    //KeyAgreement της Alice
    public KeyAgreement create_alice_key()
    { 
        try 
        {
            //Δημιουργία του κλειδιού της Alice
            aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
            alicePair = keyGen.generateKeyPair();
            aliceKeyAgree.init(alicePair.getPrivate());            
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex)
        {
            Logger.getLogger(Diffie_Hellman_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return aliceKeyAgree;
    }
    
    //Δημιουργία του τελικού κοινού κλειδιού
    public Key key_phase(KeyAgreement bob_key, KeyAgreement alice_key, String name)
    {
        Key bob = null, alice = null;
        try 
        {
            bob_key.doPhase(alicePair.getPublic(), false);
            alice_key.doPhase(bobPair.getPublic(), false);
            //Αν τα 2 κλειδιά είναι ίσα, τότε έχει δημιουργηθεί σωστά το κοινό μυστικό κλειδί και διανέμεται στους χρήστες.
            if(alice_key.doPhase(bobPair.getPublic(), false).equals(bob_key.doPhase(alicePair.getPublic(), false)))
            {
                System.out.println("The two keys are the same!");
                bob = bob_key.doPhase(alicePair.getPublic(), false);
                alice = alice_key.doPhase(bobPair.getPublic(), false);
            }
        }
        catch (InvalidKeyException | IllegalStateException ex)
        {
            Logger.getLogger(Diffie_Hellman_Class.class.getName()).log(Level.SEVERE, null, ex);
        }

        if (name.equalsIgnoreCase("bob"))
        {
            return bob;
        }
        else
        {
            return alice;
        }
    }
}