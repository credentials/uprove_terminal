package test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import net.sourceforge.scuba.smartcards.TerminalCardService;

import service.UProveService;

import com.microsoft.uprove.InvalidProofException;
import com.microsoft.uprove.Issuer;
import com.microsoft.uprove.IssuerKeyAndParameters;
import com.microsoft.uprove.IssuerParameters;
import com.microsoft.uprove.IssuerProtocolParameters;
import com.microsoft.uprove.IssuerSetupParameters;
import com.microsoft.uprove.PresentationProof;
import com.microsoft.uprove.PresentationProtocol;
import com.microsoft.uprove.Prover;
import com.microsoft.uprove.ProverProtocolParameters;
import com.microsoft.uprove.Subgroup;
import com.microsoft.uprove.UProveToken;

/**
 * This samples demonstrates how to issue and present U-Prove tokens.
 * 
 * @author Pim Vullers
 * @version $Revision: 563 $ by $Author: pim $
 *          $LastChangedDate: 2011-04-29 16:41:36 +0200 (Fri, 29 Apr 2011) $
 */
public class UProveSample {

    private static final int MAX_ATTR = 5;
    private static final int MAX_RUNS = 10;

    private static final int NUMBER_OF_TOKENS = 1;
    private static final int[] DISCLOSED = {2, 5};
    private static final String HASH_ALGORITHM_UID = "SHA-1";
    private static final byte[] ENCODING_BYTES = {
        1, 
        1, 
        1, 
        0, 
        0//*/
    };
    private static final byte[] ISSUER_PARAMETERS_UID = "Issuer parameters UID".getBytes();
    private static final byte[] ISSUER_SPECIFICATION = "Issuer parameters specification".getBytes();
    private static final byte[]	PROVER_INFORMATION = "Prover information field value".getBytes();
    private static final byte[] TOKEN_INFORMATION = "Token information field value".getBytes();
    private static final byte[] MESSAGE = "VerifierUID+random data".getBytes();

    private static final byte[][] ATTRIBUTE_VALUES = {
        "Alice Smith".getBytes(),
        "WA".getBytes(),
        "1010 Crypto Street".getBytes(),
        {0x01},
        {0x49, (byte) 0x96, 0x02, (byte) 0xD2}//*/
    };

    /**
     * Runs the sample.
     */
    public static void main(final String[] args) throws IllegalStateException, IOException, InvalidProofException, NoSuchProviderException, NoSuchAlgorithmException {
        System.out.println("U-Prove Java Card sample");

        try {
            /*
             * issuer parameters setup
             */
            /* Normal execution:*/
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.setEncodingBytes(ENCODING_BYTES);
            isp.setHashAlgorithmUID(HASH_ALGORITHM_UID);
            isp.setParametersUID(ISSUER_PARAMETERS_UID);
            isp.setSpecification(ISSUER_SPECIFICATION);
            isp.setGroup(new Subgroup(TestVectors.GROUP_P, TestVectors.GROUP_Q, TestVectors.GROUP_G));
            IssuerKeyAndParameters ikap = isp.generate();
            IssuerParameters ip = ikap.getIssuerParameters();
             
            /* Test data: 
            IssuerParameters ip = new IssuerParameters();
            ip.setEncodingBytes(ENCODING_BYTES);
            ip.setHashAlgorithmUID(HASH_ALGORITHM_UID);
            ip.setParametersUID(ISSUER_PARAMETERS_UID);
            ip.setSpecification(ISSUER_SPECIFICATION);
            ip.setGroup(new Subgroup(TestVectors.GROUP_P, TestVectors.GROUP_Q, TestVectors.GROUP_G));
            ip.setProverIssuanceValues(new byte[][]{TestVectors.Z0, TestVectors.Z1, TestVectors.Z2, TestVectors.Z3, TestVectors.Z4, TestVectors.Z5, TestVectors.ZT});
            ip.setPublicKey(new byte[][]{TestVectors.G0, TestVectors.G1, TestVectors.G2, TestVectors.G3, TestVectors.G4, TestVectors.G5, TestVectors.GT});
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.setEncodingBytes(ENCODING_BYTES);
            isp.setHashAlgorithmUID(HASH_ALGORITHM_UID);
            isp.setParametersUID(ISSUER_PARAMETERS_UID);
            isp.setSpecification(ISSUER_SPECIFICATION);
            isp.setGroup(new Subgroup(TestVectors.GROUP_P, TestVectors.GROUP_Q, TestVectors.GROUP_G));
            IssuerKeyAndParameters ikap = isp.generate();
            ikap.setIssuerParameters(ip);
            ikap.setPrivateKey(TestVectors.Y0);
            */
            // issuer distributes the issuer parameters

            // prover and verifier should validate the issuer parameters upon reception
            ip.validate();

            /*
             *  token issuance
             */
            System.out.println("###");
            System.out.println("### Issuing U-Prove tokens");
            System.out.println("###");
            
            // protocol parameters
            byte[][] attributes = ATTRIBUTE_VALUES;
            byte[] tokenInformation = TOKEN_INFORMATION;
            byte[] proverInformation = PROVER_INFORMATION;
            int numberOfTokens = NUMBER_OF_TOKENS;

            // issuer generates first issuance message
            IssuerProtocolParameters issuerProtocolParams = new IssuerProtocolParameters();
            issuerProtocolParams.setIssuerKeyAndParameters(ikap);
            issuerProtocolParams.setNumberOfTokens(numberOfTokens);
            issuerProtocolParams.setTokenAttributes(attributes);
            issuerProtocolParams.setTokenInformation(tokenInformation);
            Issuer issuer = issuerProtocolParams.generate();
            byte[][] message1 = issuer.generateFirstMessage();

            // prover generates second issuance message
            ProverProtocolParameters proverProtocolParams = new ProverProtocolParameters();
            proverProtocolParams.setIssuerParameters(ip);
            proverProtocolParams.setNumberOfTokens(numberOfTokens);
            proverProtocolParams.setTokenAttributes(attributes);
            proverProtocolParams.setTokenInformation(tokenInformation);
            proverProtocolParams.setProverInformation(proverInformation);
            TerminalFactory factory = TerminalFactory.getDefault();
            CardTerminals terminals = factory.terminals();
            CardTerminal terminal = terminals.list(CardTerminals.State.CARD_PRESENT).get(0);            
            if(!terminal.isCardPresent()) {
                throw new IllegalStateException("Card should be there, but it is not?");
            }
            Prover prover = new UProveService(new TerminalCardService(terminal));
            ((UProveService) prover).open();
            ((UProveService) prover).testMode((byte) 0x00);
            ((UProveService) prover).testMode((byte) 0x02);
            ((UProveService) prover).setProverProtocolParameters(proverProtocolParams);
            prover.precomputation();
            /* Test data: 
            message1 = new byte[][]{TestVectors.SIGMA_A, TestVectors.SIGMA_B});
            */
            byte[][] message2 = prover.generateSecondMessage(message1);

            // issuer generates third issuance message
            byte[][] message3 = issuer.generateThirdMessage(message2);

            // prover generates the U-Prove tokens
            /* Test data:
            message3 = new byte[][]{TestVectors.SIGMA_R});
            */
            prover.generateTokens(message3);

            // application specific storage of keys, tokens, and attributes

            /*
             * token presentation
             */
            System.out.println("###");
            System.out.println("### Presenting a U-Prove token");
            System.out.println("###");
            
            // protocol parameters (shared by prover and verifier)
            int[] disclosed = DISCLOSED;
            byte[] message = MESSAGE;

            for (int r = 0; r < MAX_RUNS; r++) {
                System.out.println("\n\n\n\n### Run " + (r+1) + " of " + MAX_RUNS + "\n");
            for (int i = 0; i <= MAX_ATTR; i++) {
                System.out.println("\n### Disclosing " + i + " attributes\n");
                for (int j = 0; j < 5; j++) {
                    switch(i) {
                        case 0: 
                            disclosed = new int[0];
                            break;
                        case 1:
                            disclosed = new int[]{(j % MAX_ATTR) + 1};
                            break;
                        case 2:
                            disclosed = new int[]{(j % MAX_ATTR) + 1, ((j+1) % MAX_ATTR) + 1};
                            break;
                        case 3:
                            disclosed = new int[]{(j % MAX_ATTR) + 1, ((j+1) % MAX_ATTR) + 1, ((j+2) % MAX_ATTR) + 1};
                            break;
                        case 4:
                            disclosed = new int[]{(j % MAX_ATTR) + 1, ((j+1) % MAX_ATTR) + 1, ((j+2) % MAX_ATTR) + 1, ((j+3) % MAX_ATTR) + 1};
                            break;
                        case 5:
                            disclosed = new int[]{1, 2, 3, 4, 5};
                            break;
                    }
                    
                    System.out.print("### D: ");
                    for (int k = 0; k < disclosed.length; k++) {
                        System.out.print(disclosed[k] + " ");
                    }
                    
                    // prover generates the presentation proof
                    PresentationProof proof = ((UProveService)prover).generateProof(disclosed, message);

                    // prover transmits the U-Prove token and presentation proof to the verifier 
                    UProveToken token = ((UProveService)prover).getUProveToken();

                    // verifier verifies the presentation proof
                    PresentationProtocol.verifyPresentationProof(ip, disclosed, message, null, token, proof);
                }
            }
            }
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace(System.out);
            return;
        }

        System.out.println("Sample completed successfully");
    }
}
