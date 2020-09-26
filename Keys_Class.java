
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jcajce.util.*;

public class Keys_Class
{
    private KeyPair keypair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private X509Certificate cert;/** This holds the certificate of the CA used to sign the new certificate. The object is created in the constructor. */
   
    public KeyPair generateRSAkey()//Γεννήτρια ζευγαριού κλειδιών
    {
        try 
        {
            Security.addProvider(new BouncyCastleProvider());//Πάροχος θα είναι η Bouncy Castle
            //Δημιουργία της γεννήτριας, στην οποία ορίζουμε τον αλγόριθμο κρυπτογράφησης που θέλουμε να φτιάξει κλειδιά
            //Καθώς και τον πάροχο
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(2048);//Κλειδιά μήκους 2048 bits
            keypair = generator.genKeyPair();
            
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return keypair;
    }
    
    public PrivateKey private_key_gen()//Δημιουργία του ιδιωτικού κλειδιού
    {
        privateKey = keypair.getPrivate();
        
        return privateKey;
    }
    
    public PublicKey public_key_gen()//Δημιουργία του δημόσιου κλειδιού
    {
        publicKey = keypair.getPublic();
        
        return publicKey;
    }
    
    //Δημιουργία πιστοποιητικού
    public X509Certificate generate_certificates(PublicKey publicKey, PrivateKey privateKey, String cert_name, String Name, String Issuer) throws InvalidCipherTextException, FileNotFoundException
    {
        try 
        {
            Provider bcProvider = new BouncyCastleProvider();//Ορισμός παρόχου
            Security.addProvider(bcProvider);
            //Όνομα χρήστη του πιστοποιητικού
            X500Name dnName = new X500Name(Name);
            //Όνομα υπογράφοντος
            X500Name isName = new X500Name(Issuer);
            long now = System.currentTimeMillis();
            Date startDate = new Date(now);//Ημερομηνία έκδοσης

            BigInteger certSerialNumber = new BigInteger(Long.toString(now)); //Χρησιμοποιούμε την τρέχουσα χρονοσφραγίδα ως αριθμό πιστοποιητικού για να πετύχουμε μοναδικότητα

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(startDate);
            calendar.add(Calendar.YEAR, 1); // 1 χρόνο διάρκεια ζωής το πιστοποιητικό
            Date endDate = calendar.getTime();
            BasicConstraints basicConstraints;//BasicConstraints αντικείμενο της BouncyCastle
            
            if(Name.equals("CN=Iason Demertzidis,OU=321/2012048") || Name.equals("CN=Nikos Stergiopoulos,OU=321/2011154") || Name.equals("CN=Vasilis Arapantzis,OU=321/2013015"))//Αν το όνομα χρήστη του πιστοποιητικού είναι η CA
            {
                basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
            }
            else
            {
                basicConstraints = new BasicConstraints(false); // <-- true for CA, false for EndEntity
            }
            
            //Δημιουργία ενός X509v3CertificateBuilder αντικειμένου, στο οποίο θα βάλουμε όλες τις παραπάνω παραμέτρους
            //Και θα προσθέσουμε ένα extension το οποίο παίρνει ως ορίσματα: 
            //ASN1ObjectIdentifier("2.5.29.19") --> Το πιστοποιητικό μπορεί να συμπεριφέρεται σαν CA
            //true --> isCritical μέθοδος που ορίζει ότι το πιστοποιητικό είναι κρίσιμο
            //basicConstraints --> Σε ένα certificate chain, η CA πρέπει να έχει δικαίωμα να ορίζει αν ένα πιστοποιητικό που υπογράφει, έχει δικαίωμα να υπογράφει πιστοποιητικά
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(isName, certSerialNumber, startDate, endDate, dnName, publicKey)
                    .addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);
            
            //Αντικείμενο τύπου ContentSigner που ορίζει τον αλγόριθμο κρυπτογράφησης, των αλγόριθμο κατακερματισμού, τον πάροχο και το ιδιωτικό κλειδί με το οποίο θα υπογράψει το πιστοποιητικό
            ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(bcProvider).build(privateKey);
            //Τελικώς, μετατροπή του ContentSigner αντικειμένου σε X509 και δημιουργία του τελικού πιστοποιητικού.
            cert = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(sigGen));

            System.out.println(cert_name + " has been created!");
           
        }
        catch (IOException | CertificateException | OperatorCreationException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return cert;
    }
    
    //Δημιουργία αλυσίδας πιστοποιητικών
    public void create_cert_chain(String cert_name[], String alias[], String pass_Alice, String pass_Bob, X509Certificate Cert[], PrivateKey privKey[])
    {
        FileOutputStream bob_fos = null, alice_fos = null, fos1 = null;
        try 
        {
            //2 αλυσίδες πιστοποιητικών, μια για τον Bob μια για την Alice
            X509Certificate[] chain_bob = new X509Certificate[3];
            X509Certificate[] chain_alice = new X509Certificate[3];
            //Ορισμός του παρόχου
            Provider bcProvider = new BouncyCastleProvider();
            Security.addProvider(bcProvider);
            //Δημιουργία 2 keystore για την καταχώρηση των πιστοποιητικών
            KeyStore bob_store = KeyStore.getInstance("JKS");
            KeyStore alice_store = KeyStore.getInstance("JKS");
            //αρχικοποίηση
            bob_store.load(null, null);
            alice_store.load(null, null);
            //Δημιουργία των keystores
            bob_fos = new FileOutputStream("Bob Keystore.keystore");
            alice_fos = new FileOutputStream("Alice Keystore.keystore");
            
            //Certificate chain για τον Bob            
            chain_bob[0] = Cert[4];//Πρώτο το πιστοποιητικό του Βob
            chain_bob[1] = Cert[3];//Δεύτερο το πιστοποιητικό της Intermediate CA
            chain_bob[2] = Cert[0];//Τρίτο το πιστοποιητικό της CA.
            
            //Για να αποκτήσουμε πρόσβαση στο keystore, θα πρέπει να δώσουμε το σωστό pass_Bob το οποίο θα αντιστοιχηθεί με το ψευδώνυμο και θα επιτρέψει την πρόσβαση 
            bob_store.setKeyEntry("Bob's verification chain", privKey[0], pass_Bob.toCharArray(), chain_bob);
            
            //Certificate chain για την Alice
            chain_alice[0] = Cert[2];//Πρώτο το πιστοποιητικό της Alice
            chain_alice[1] = Cert[1];//Δεύτερο το πιστοποιητικό της Intermediate CA
            chain_alice[2] = Cert[0];//Τρίτο το πιστοποιητικό της CA.
            alice_store.setKeyEntry("Alice's verification chain", privKey[1], pass_Alice.toCharArray(), chain_alice);
            
            for(int i=0; i<5; i++)
            {
                //Αποθήκευση των πιστοποιητικών σε αρχεία εξόδου
                fos1 = new FileOutputStream(cert_name[i]);
                fos1.write(Cert[i].getEncoded());
                fos1.flush();
            }
            
            
            //Αποθήκευση των αρχείων στα οποία υπάρχουν τα πιστοποιητικά στα αντίστοιχα keystores
            bob_store.store(bob_fos, pass_Bob.toCharArray());
            alice_store.store(alice_fos, pass_Alice.toCharArray());
            
            //κλείσιμο των ροών
            bob_fos.close();
            alice_fos.close();
            fos1.close();
            System.out.println("The certificate chains have been created!");
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch(NullPointerException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //Αυθεντικοποίηση
    public boolean authentication(String name, String pass_Alice, String pass_Bob, PublicKey publicKey_CA, PublicKey publicKey_Interm)
    {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        boolean status = false;
        Certificate chain[] = null;
        FileInputStream bob_fos = null, alice_fos = null;
        try 
        {
            //Δημιουργία 2 αντικειμένων της κλάσης Κeystore
            KeyStore bob_store = KeyStore.getInstance("JKS");
            KeyStore alice_store = KeyStore.getInstance("JKS");
            
            if(name.equalsIgnoreCase("Bob"))//Όταν θέλει ο Bob να αυθεντικοποιήση την Alice
            {
                System.out.println("Bob will try to verify Alice's authenticity.");
                alice_fos = new FileInputStream("Alice Keystore.keystore");//Άνοιγμα μιας ροής ανάγνωσης αρχείων
                alice_store.load(alice_fos, pass_Alice.toCharArray());//Φόρτωση του keystore της Αlice, μαζί με το συνθηματικό με το οποίο προστατεύει το keystore
                chain = (Certificate[]) alice_store.getCertificateChain("Alice's verification chain");//Παίρνει την αλυσίδα από το keystore
                
                //Έλεγχος των πιστοποιητικών της αλυσίδας
                //Ο έλεγχος γίνεται πρώτα στης Alice, με τη χρήση του δημόσιου κλειδιού του ICA
                //Μετά γίνεται στην ICA με τη χρήση του δημόσιου κλειδιού της CA
                //Τέλος γίνεται στη CA με τη χρήση του δημόσιου κλειδιού της CA
                chain[0].verify(publicKey_Interm, bcProvider);
                chain[1].verify(publicKey_CA, bcProvider);
                chain[2].verify(publicKey_CA, bcProvider);
                //Άμα υπάρχει λάθος σε κάποιο από τα πιστοποιητικά θα χτυπήσει exception και θα τερματίσει το πρόγραμμα
                status = true;
            }
            else if(name.equalsIgnoreCase("Alice"))//Όταν θέλει η Alice να αυθεντικοποιήση τον Bob
            {
                System.out.println("Alice will try to verify Bob's authenticity.");
                bob_fos = new FileInputStream("Bob Keystore.keystore");//Άνοιγμα μιας ροής ανάγνωσης αρχείων
                bob_store.load(bob_fos, pass_Bob.toCharArray());//Φόρτωση του keystore του Bob, μαζί με το συνθηματικό με το οποίο προστατεύει το keystore
                chain = (Certificate[]) bob_store.getCertificateChain("Bob's verification chain");//Παίρνει την αλυσίδα από το keystore
 
                //Έλεγχος των πιστοποιητικών της αλυσίδας
                //Ο έλεγχος γίνεται πρώτα στον Bob, με τη χρήση του δημόσιου κλειδιού του ICB
                //Μετά γίνεται στην ICA με τη χρήση του δημόσιου κλειδιού της CA
                //Τέλος γίνεται στη CA με τη χρήση του δημόσιου κλειδιού της CA
                chain[0].verify(publicKey_Interm, bcProvider);
                chain[1].verify(publicKey_CA, bcProvider);
                chain[2].verify(publicKey_CA, bcProvider);
                //Άμα υπάρχει λάθος σε κάποιο από τα πιστοποιητικά θα χτυπήσει exception και θα τερματίσει το πρόγραμμα
                status = true;
            }
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Keys_Class.class.getName()).log(Level.SEVERE, null, ex);
        }
        return status;
    }    
}
