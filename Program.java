import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

public class Program 
{
    //Κλειδιά και πιστοποιητικά για τους χρήστες, την ca και τις intermediate ca 
    private PublicKey publicKey_CA, publicKey_Bob, publicKey_Alice, publicKey_inA, publicKey_inB;
    private PrivateKey privateKey_CA, privateKey_Bob, privateKey_Alice, privateKey_inA, privateKey_inB;
    private KeyAgreement bob_KeyAgree, alice_KeyAgree;
    private Key alice_diffie_hellman_key;
    private Key bob_diffie_hellman_key;
    public X509Certificate caCert, inCertA, inCertB, Bob_Cert, Alice_Cert;
    public X509Certificate cert_array[] = new X509Certificate[5];
    
    public void run_program()
    {
        //Τα ονόματα των αρχείων που θα αποθηκευτούν τα κλειδιά σε μορφή .key
        String BOB_PUBLIC_KEY_FILE = "Bob Public key.key";
        String BOB_PRIVATE_KEY_FILE = "Bob Private key.key";
        String ALICE_PUBLIC_KEY_FILE = "Alice Public key.key";
        String ALICE_PRIVATE_KEY_FILE = "Alice Private key.key";
        String CA_PUBLIC_KEY_FILE = "CA Public key.key";
        String CA_PRIVATE_KEY_FILE = "CA Private key.key";
        String AES_KEY_FILE = "Aes key.key";
        String ICA_PUBLIC_KEY_FILE = "Intermediate Certificate for Alice Public key.key";
        String ICA_PRIVATE_KEY_FILE = "Intermediate Certificate for Alice Private.key";
        String ICB_PUBLIC_KEY_FILE = "Intermediate Certificate for Bob Public.key";
        String ICB_PRIVATE_KEY_FILE = "Intermediate Certificate for Bob Private.key";
        
        try 
        {
            String client_name, ans;
            int choise;
            boolean bob_created = false, alice_created = false;
            byte[] encrypted_secret_key = null;
            String cert_name[] = new String[5];
            String alias[] = new String[5];
            String pass_Alice = "University", pass_Bob = "Of Aegean";//Κωδικοί για τα KeyStores
            
            //Έναρξη αυτοματοποιημένων διαδικασιών
            
            Scanner scan = new Scanner(System.in);
            //Δημιουργία αντικειμένου της Root CA και των Intermediate CA.
            Keys_Class ca_keys = new Keys_Class();
            Keys_Class inA_keys = new Keys_Class();
            Keys_Class inB_keys = new Keys_Class();
            
            //Δημιουργία rsa κλειδιών για την CA
            //Δημιουργία πιστοποιητικού υπογεγραμμένο από την CA (self signed)
            cert_name[0] = "CA.crt";
            alias[0] = "CA";
            ca_keys.generateRSAkey();//Κλήση της γεννήτριας ζευγαριών κλειδιών
            publicKey_CA = ca_keys.public_key_gen();//Κλήση της μεθόδου δημιουργίας δημόσιου κλειδιού
            privateKey_CA = ca_keys.private_key_gen();//Κλήση της μεθόδου δημιουργίας ιδιωτικού κλειδιού
            //Δημιουργία του πιστοποιητικού της Certificate Authority. Είναι self signed οπότε, θα υπογραφεί με το ιδιωτικό της κλειδί
            //Οι παράμετροι που παίρνει είναι το δημόσιο κλειδί που θα περιέχει, το ιδιωτικό κλειδί που θα την υπογράφει, το όνομα του πιστοποιητικού, ονομασία παραλήπτη και ονομασία υπογράφοντος
            caCert = ca_keys.generate_certificates(publicKey_CA, privateKey_CA, cert_name[0], "CN=Iason Demertzidis,OU=321/2012048", "CN=Iason Demertzidis,OU=321/2012048");
            cert_array[0] = caCert;//Ο πίνακας πιστοποιητικών θα χρησιμεύσει στη δημιουργία των certificate chains
            
            //Δημιουργία rsa κλειδιών για την Intermediate Certificate της Alice
            //Δημιουργία πιστοποιητικού υπογεγραμμένο από την CA
            cert_name[1] = "ICA.crt";
            alias[1] = "ICA";
            inA_keys.generateRSAkey();//Κλήση της γεννήτριας ζευγαριών κλειδιών
            publicKey_inA = inA_keys.public_key_gen();//Κλήση της μεθόδου δημιουργίας δημόσιου κλειδιού
            privateKey_inA = inA_keys.private_key_gen();//Κλήση της μεθόδου δημιουργίας ιδιωτικού κλειδιού
            //Δημιουργία του πιστοποιητικού της Intermediate Certificate Authority που θα αφορά την Alice (ICA). Είναι signed από την CA οπότε, θα υπογραφεί με το ιδιωτικό κλειδί της CA
            //Οι παράμετροι που παίρνει είναι το δημόσιο κλειδί που θα περιέχει, το ιδιωτικό κλειδί που θα την υπογράφει, το όνομα του πιστοποιητικού, ονομασία παραλήπτη και ονομασία υπογράφοντος
            inCertA = inA_keys.generate_certificates(publicKey_inA, privateKey_CA, cert_name[1], "CN=Vasilis Arapantzis,OU=321/2013015", "CN=Iason Demertzidis,OU=321/2012048");
            cert_array[1] = inCertA;
            
            //Private and public key που θα χρησιμοποιεί η Alice για την κρυπτογράφηση και αποκρυπτογράφηση του συμμετρικού κλειδιού
            //Δημιουργία πιστοποιητικού υπογεγραμμένο από την intermediate authority της Alice
            cert_name[2] = "Alice.crt";
            alias[2] = "AC";
            Keys_Class Alice = new Keys_Class();//Δημιουργία του πρώτου αντικειμένου-πελάτη που θα λέγεται Alice 
            Alice.generateRSAkey();//Κλήση της γεννήτριας ζευγαριών κλειδιών
            publicKey_Alice = Alice.public_key_gen();//Κλήση της μεθόδου δημιουργίας δημόσιου κλειδιού
            privateKey_Alice = Alice.private_key_gen();//Κλήση της μεθόδου δημιουργίας ιδιωτικού κλειδιού
            //Δημιουργία του πιστοποιητικού της Alice. Είναι signed από την ICA, θα υπογραφεί με το ιδιωτικό κλειδί της ICA
            //Οι παράμετροι που παίρνει είναι το δημόσιο κλειδί που θα περιέχει, το ιδιωτικό κλειδί που θα την υπογράφει, το όνομα του πιστοποιητικού, ονομασία παραλήπτη και ονομασία υπογράφοντος
            Alice_Cert = Alice.generate_certificates(publicKey_Alice, privateKey_inA, cert_name[2], "CN=Alice Alice,OU=321/2017002", "CN=Vasilis Arapantzis,OU=321/2013015");
            cert_array[2] = Alice_Cert;
            
            
            //Δημιουργία rsa κλειδιών για την intermediate certificate του Bob
            //Δημιουργία πιστοποιητικού υπογεγραμμένο από την CA
            cert_name[3] = "ICB.crt";
            alias[3] = "ICB";
            inB_keys.generateRSAkey();//Κλήση της γεννήτριας ζευγαριών κλειδιών
            publicKey_inB = inB_keys.public_key_gen();//Κλήση της μεθόδου δημιουργίας δημόσιου κλειδιού
            privateKey_inB = inB_keys.private_key_gen();//Κλήση της μεθόδου δημιουργίας ιδιωτικού κλειδιού//Κλήση της μεθόδου δημιουργίας ιδιωτικού κλειδιού
            //Δημιουργία του πιστοποιητικού της Intermediate Certificate Authority που θα αφορά τον Βοb (ICB). Είναι signed από την CA οπότε, θα υπογραφεί με το ιδιωτικό κλειδί της CA
            //Οι παράμετροι που παίρνει είναι το δημόσιο κλειδί που θα περιέχει, το ιδιωτικό κλειδί που θα την υπογράφει, το όνομα του πιστοποιητικού, ονομασία παραλήπτη και ονομασία υπογράφοντος
            inCertB = inB_keys.generate_certificates(publicKey_inB, privateKey_CA, cert_name[3], "CN=Nikos Stergiopoulos,OU=321/2011154", "CN=Iason Demertzidis,OU=321/2012048");
            cert_array[3] = inCertB;
            
            //Private and public key που θα χρησιμοποιεί ο Bob για την κρυπτογράφηση και αποκρυπτογράφηση του συμμετρικού κλειδιού
            //Δημιουργία του πιστοποιητικού του Bob, υπογεγραμμένο από την intermediate authority του Bob
            cert_name[4] = "Bob.crt";
            alias[4] = "BC";
            Keys_Class Bob = new Keys_Class();//Δημιουργία του δεύτερου αντικειμένου-πελάτη που θα λέγεται Alice 
            Bob.generateRSAkey();//Κλήση της γεννήτριας ζευγαριών κλειδιών
            publicKey_Bob = Bob.public_key_gen();//Κλήση της μεθόδου δημιουργίας δημόσιου κλειδιού
            privateKey_Bob = Bob.private_key_gen();//Κλήση της μεθόδου δημιουργίας ιδιωτικού κλειδιού
            //Δημιουργία του πιστοποιητικού της Alice. Είναι signed από την ICB, θα υπογραφεί με το ιδιωτικό κλειδί της ICB
            //Οι παράμετροι που παίρνει είναι το δημόσιο κλειδί που θα περιέχει, το ιδιωτικό κλειδί που θα την υπογράφει, το όνομα του πιστοποιητικού, ονομασία παραλήπτη και ονομασία υπογράφοντος
            Bob_Cert = Bob.generate_certificates(publicKey_Bob, privateKey_inB, cert_name[4], "CN=Bob Bob,OU=321/2017001", "CN=Nikos Stergiopoulos,OU=321/2011154");
            cert_array[4] = Bob_Cert;
            
            //Κρατάμε σε έναν πίνακα τα ιδιωτικά κλειδιά των δύο intermediate CA
            PrivateKey privKey[] = new PrivateKey[2];
            privKey[0] = privateKey_inB;
            privKey[1] = privateKey_inA;
            
            //Δημιουργία των αλυσίδων πιστοποιητικών
            //Παίρνουν ως παράμετρο τους πίνακες με τα ονόματα των πιστοποιητικών, τα ψευδόνυμα, τους κωδικούς για τα keystores, τα πιστοποιητικά και τα ιδιωτικά κλειδιά των Intermediate ca.
            ca_keys.create_cert_chain(cert_name, alias, pass_Alice, pass_Bob, cert_array, privKey);
            
            Diffie_Hellman_Class DHC = new Diffie_Hellman_Class();//Δημιουργία ενός αντικειμένου της κλάσης Diffie_Hellman_Class
            
            DHC.create_same_number();//Δημιουργία του κοινού αριθμού Diffie-Hellman
            
            StoreKeys_Class StoreKeys = new StoreKeys_Class();//Δημιουργία ενός αντικειμένου της κλάσης StoreKeys_Class
            //Αποθήκευση όλων των κλειδιών στα αντίστοιχα αρκεία.
            StoreKeys.store_rsa_keys(BOB_PUBLIC_KEY_FILE, BOB_PRIVATE_KEY_FILE, publicKey_Bob, privateKey_Bob);
            StoreKeys.store_rsa_keys(ALICE_PUBLIC_KEY_FILE, ALICE_PRIVATE_KEY_FILE, publicKey_Alice, privateKey_Alice);
            StoreKeys.store_rsa_keys(CA_PUBLIC_KEY_FILE, CA_PRIVATE_KEY_FILE, publicKey_CA, privateKey_CA);
            StoreKeys.store_rsa_keys(ICA_PUBLIC_KEY_FILE, ICA_PRIVATE_KEY_FILE, publicKey_inA, privateKey_inA);
            StoreKeys.store_rsa_keys(ICB_PUBLIC_KEY_FILE, ICB_PRIVATE_KEY_FILE, publicKey_inB, privateKey_inB);
            System.out.println("\n");
            //Τέλος αυτοματοποιημένων διαδικασιών
            //Έναρξη προγράμματος
            do
            {
                System.out.print("What is your name? ");//Ο Χρήστης δίνει το όνομά του.
                client_name = scan.next();
                System.out.println("\n");
                if (client_name.equalsIgnoreCase("Bob"))//Δεν υπάρχει περιορισμός στο πως θα γράψει το όνομά του(κεφαλαία, πεζά, κλπ)
                {
                    menu();//Κλήση της μεθόδου που θα εμφανίσει το μενου
                    choise = scan.nextInt();//Ο Bob επιλέγει
                    Encapsulation_Class EC_Bob = new Encapsulation_Class();//Δημιουργείται ένα αντικείμενο της κλάσης Encapsulation
                    while (choise != 0)
                    {
                        if (choise == 1)//Πρώτη επιλογή, ενθυλάκωση του κοινού μυστικού κλειδιού που θα δημιουργήσει ο Bob με το δημόσιο κλειδί της Alice
                        {
                            boolean cond = false;
                            //Ο Βob θέλει να αυθεντικοποιήσει την Alice,
                            PublicKey Exp_publicKey_CA;//Experimental public key της CA.
                            PublicKey Exp_publicKey_inA;//Experimental public key της ICA.
                            
                            //Export των κλειδιών της CA και ICA από τα αρχεία 
                            Exp_publicKey_CA = StoreKeys.readPublicKey(CA_PUBLIC_KEY_FILE);
                            Exp_publicKey_inA = StoreKeys.readPublicKey(ICA_PUBLIC_KEY_FILE);
                            //Μέδοδος boolean για το εάν ή όχι, βάσει των δημόσιων κλειδιών της Intermediate Certificate Authority της Alice και της CA, η Alice είναι πιστοποιημένη
                            cond = Bob.authentication(client_name, pass_Alice, pass_Bob, Exp_publicKey_CA, Exp_publicKey_inA);
                            
                            if(cond == true)//Αν ναι, τότε δημιουργείται ένα AES key, κρυπτογραφείται με το δημόσιο κλειδί της Alice και αποθηκεύεται σε αρχείο
                            {
                                SecretKey secret_key = EC_Bob.aes_key_generation();
                                encrypted_secret_key = EC_Bob.encrypt(publicKey_Alice, secret_key);
                                System.out.println("The secret key is encrypted!");
                                StoreKeys.store_aes_keys(AES_KEY_FILE, secret_key);
                                System.out.println("Authentication successful!");
                            }
                            else
                            {
                                System.out.println("The authentication of Alice was unsuccessful");
                            }
                        }
                        else if (choise == 2)//Δημιουργία του αριθμού Diffie-Hellman που θα στείλει ο Bob
                        {
                            bob_KeyAgree = DHC.create_bob_key();
                            bob_created = true;
                            System.out.println("Bob's key has been created!");
                        }
                        else if(choise == 3)//Δημιουργία του αριθμού Diffie-Hellman του Bob, αφού γίνει αυθεντικοποίηση της Alice
                        {
                            boolean cond = false;
                            //Ο Βob θέλει να αυθεντικοποιήσει την Alice,
                            PublicKey Exp_publicKey_CA;//Experimental public key της CA.
                            PublicKey Exp_publicKey_inA;//Experimental public key της ICA.
                            
                            //Export των κλειδιών της CA και ICA από τα αρχεία 
                            Exp_publicKey_CA = StoreKeys.readPublicKey(CA_PUBLIC_KEY_FILE);
                            Exp_publicKey_inA = StoreKeys.readPublicKey(ICA_PUBLIC_KEY_FILE);
                            //Μέδοδος boolean για το εάν ή όχι, βάσει των δημόσιων κλειδιών της Intermediate Certificate Authority της Alice και της CA, η Alice είναι πιστοποιημένη                            
                            cond = Bob.authentication(client_name, pass_Alice, pass_Bob, Exp_publicKey_CA, Exp_publicKey_inA);
                            if(cond == true)//Αν ναι, τότε δημιουργείται ο αριθμός Diffie-Hellman του Bob
                            {
                                bob_KeyAgree= DHC.create_bob_key();
                                bob_created = true;
                                System.out.println("Bob's key has been created!");
                            }
                            else
                            {
                                System.out.println("The authentication of Alice was unsuccessful");
                            }
                        }
                        else if (choise == 4)//Αποκρυπτογράφηση του AES key
                        {
                            if(encrypted_secret_key == null)//Έλεγχος ύπαρξεις του AES key
                            {
                                System.out.println("You forgot to encrypt the secret key.");
                            }
                            else//Η αποκρυπτογράφηση γίνεται με το ιδιωτικό κλειδί του bob και το κρυπτογραφημένο AES key
                            {
                                SecretKey decrypted_secret_key = EC_Bob.decrypt(privateKey_Bob, encrypted_secret_key);
                                System.out.println("Secret key decrypted!");
                            }
                        }
                        else if(choise == 5)//Δημιουργία του κοινού κλειδιού Diffie-Hellman
                        {
                            if((bob_created == true) && (alice_created == true))//Έλεγχος αν και οι 2 χρήστες έχουν φτιάξει τους αριθμούς τους
                            {
                                System.out.println("Key created!");
                                bob_diffie_hellman_key = DHC.key_phase(bob_KeyAgree, alice_KeyAgree, client_name);//Μέθοδος δημιουργίας
                            }
                            else if(bob_created == false)
                            {
                                System.out.println("Bob's key has not been created yet");
                            }
                            else if(alice_created == false)
                            {
                                System.out.println("Alice's key has not been created yet");
                            }
                        }
                        //Ο χρήστης μπορεί να τρέχει το πρόγραμμα μέχρι να επιλέξει 0
                        menu();
                        choise = scan.nextInt();
                    }
                }
                else if (client_name.equalsIgnoreCase("Alice"))//Αν μπει η Alice στην εφαρμογή
                {
                    menu();
                    choise = scan.nextInt();
                    Encapsulation_Class EC_Alice = new Encapsulation_Class();//Δημιουργία ενός αντικειμένου της κλάσης Encapsulation 
                    while (choise != 0)
                    {
                        if (choise == 1)
                        {
                            boolean cond = false;
                            PublicKey Exp_publicKey_CA;//Experimental public key της CA.
                            PublicKey Exp_publicKey_inB;//Experimental public key της CAB.
                            //Export των δημόσιων κλειδιών της CA και της CAB για την πιστοποίηση του Bob από την Alice
                            Exp_publicKey_CA = StoreKeys.readPublicKey(CA_PUBLIC_KEY_FILE);
                            Exp_publicKey_inB = StoreKeys.readPublicKey(ICB_PUBLIC_KEY_FILE);
                            //Boolean μέθοδος που θα ελέγξει αν είναι πιστοποιημένος ο Bob
                            cond = Alice.authentication(client_name, pass_Alice, pass_Bob, Exp_publicKey_CA, Exp_publicKey_inB);
                            
                            if(cond == true)//Αν ναι, δημιουργία του AES κλειδιού και κρυπτογράφησή του με το δημόσιο κλειδί του Bob και αποθήκευση σε αρχείο
                            {
                                System.out.println("Authentication was successful!");
                                SecretKey secret_key = EC_Alice.aes_key_generation();
                                encrypted_secret_key = EC_Alice.encrypt(publicKey_Bob, secret_key);
                                System.out.println("The secret key is encrypted!");
                                StoreKeys.store_aes_keys(AES_KEY_FILE, secret_key);  
                            }
                            else
                            {
                                System.out.println("The authentication of Alice was unsuccessful");
                            }                
                        }
                        else if (choise == 2)//Δημιουργία του αριθμού Diffie-Hellman της Alice
                        {
                            System.out.println("\nAlice's key has been created!");
                            alice_KeyAgree = DHC.create_alice_key();
                            alice_created = true;
                        }
                        else if (choise == 3)//Δημιουργία του αριθμού Diffie-Hellman της Alice αφού γίνει αυθεντικοποίηση του Βοb
                        {
                            boolean cond = false;
                            PublicKey Exp_publicKey_CA;//Experimental public key της CA.
                            PublicKey Exp_publicKey_inB;//Experimental public key της CAB.
                            //Export των δημόσιων κλειδιών της CA και της CAB για την πιστοποίηση του Bob από την Alice
                            Exp_publicKey_CA = StoreKeys.readPublicKey(CA_PUBLIC_KEY_FILE);
                            Exp_publicKey_inB = StoreKeys.readPublicKey(ICB_PUBLIC_KEY_FILE);
                            //Boolean μέθοδος που θα ελέγξει αν είναι πιστοποιημένος ο Bob                            
                            cond = Bob.authentication(client_name, pass_Alice, pass_Bob, Exp_publicKey_CA, Exp_publicKey_inB);
                            
                            if(cond == true)//Αν είναι, τότε θα δημιουργήσει η Alice των αριθμό της
                            {
                                System.out.println("\nAlice's key has been created!");
                                alice_KeyAgree = DHC.create_alice_key();
                                alice_created = true;
                            }
                            else
                            {
                                System.out.println("The authentication of Alice was unsuccessful");
                            } 
                        }
                        else if (choise == 4)//Αποκρυπτογράφηση του κρυπτογραφημένου AES key με τη χρήση του ιδιωτικού κλειδιού της
                        {
                            SecretKey decrypted_secret_key = EC_Alice.decrypt(privateKey_Alice, encrypted_secret_key);
                            System.out.println("\nSecret key decrypted");
                        }
                        else if(choise == 5)//Δημιουργία του κοινού κλειδιού Diffie-Hellman
                        {
                            if((bob_created == true) && (alice_created == true))//Αν και οι 2 χρήστες έχουν δημιουργήσει του αριθμούς τους τότε φτιάχνεται το κλειδί
                            {
                                System.out.println("Key created!");
                                alice_diffie_hellman_key = DHC.key_phase(bob_KeyAgree, alice_KeyAgree, client_name);
                            }
                            else if(bob_created == false)
                            {
                                System.out.println("Bob's key has not been created yet");
                            }
                            else if(alice_created == false)
                            {
                                System.out.println("Your key has not been created yet");
                            }
                            else
                            {
                                System.out.println("There is something wrong with the Diffie-Hellman algorithm.");
                            }
                        }
                        //Ο χρήστης μπορεί να τρέχει το πρόγραμμα μέχρι να επιλέξει 0
                        menu();
                        choise = scan.nextInt();
                    }
                }
                else//Έλεγχος ορθότητας ονόματος
                {
                    System.out.println("Acceptable names are bob and alice");
                }
                System.out.println("Log in with different account? (Yes or No)");
                ans = scan.next();
            } while (ans.equalsIgnoreCase("yes"));
        }catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    //Μέθοδος μενού επιλογών
    public void menu()
    {
        System.out.println("Choose one from below:");
        System.out.println("0. Exit.");
        System.out.println("1. Encapsulation.");
        System.out.println("2. Diffie-Hellman.");
        System.out.println("3. Station to Station.");
        System.out.println("4. Decrypt secret key from Encapsulation.");
        System.out.println("5. Create key for Diffie Hellman/StS.");
    }
}