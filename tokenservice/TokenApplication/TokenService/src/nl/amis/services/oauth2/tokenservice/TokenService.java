package nl.amis.services.oauth2.tokenservice;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import java.nio.charset.Charset;

import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import oracle.adf.share.logging.ADFLogger;

import oracle.security.jps.JpsContext;
import oracle.security.jps.JpsContextFactory;
import oracle.security.jps.service.keystore.KeyStoreService;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

@Path("tokenservice")
public class TokenService {
    private static KeyStore ks;
    private static Properties prop;
    private static ADFLogger logger = ADFLogger.createADFLogger(TokenService.class);
    private static final String propertiesfile = "nl/amis/services/oauth2/tokenservice/TokenApplication.properties";
    private void initProperties() throws IOException {
        if (prop == null) {
            logger.info("Loading properties from: " + propertiesfile);
            InputStream is = TokenResource.class.getClassLoader().getResourceAsStream(propertiesfile);
            prop = new Properties();
            prop.load(is);
            logger.fine("Properties have been loaded: Size: "+Integer.toString(prop.size()));
        } else {
            logger.fine("Properties have already been loaded");
        }
    }

    public TokenService() throws IOException {
        super();
        logger.fine("TokenService constructor called");
        initProperties();
        logger.fine("TokenService constructor completed");
    }

    @POST
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    @Path("/")
    public String tokenservice(@Context ContainerRequestContext crs) {
        SecurityContext sc = crs.getSecurityContext();
        String req = convertStreamToString(crs.getEntityStream());
        String user = "";
        String token = "";
        String output = "";
        Long expirytime = new Long(0);
        try {
            String name="";
            String value="";
            Boolean found_client_credentials_request = false;
            
            List<NameValuePair> pairs = URLEncodedUtils.parse(req, Charset.forName("UTF-8"));
            for (NameValuePair i: pairs) {
                  name = i.getName();
                  value = i.getValue();
                  if (name.equals("grant_type") && value.equals("client_credentials")) {
                    found_client_credentials_request=true;
                    break;
                  }
            }
            if (!found_client_credentials_request) {
                throw new Exception("Grant type requested is not 'client credentials'. Request body: "+req);
            } else {
                logger.fine("Request received. 'grant_type=client_credentials'");
            }
            
            logger.fine("Determining principle from SecurityContext");
            if (sc != null) {
                Principal p = sc.getUserPrincipal();
                if (p != null) {
                    user = p.getName();
                } else {
                    throw new Exception("Critical error: Principal (user name) in SecurityContext is empty!");
                }
            } else {
                throw new Exception("Critical error: Security context is absent!");
            }

            AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    try {
                        JpsContext ctx = JpsContextFactory.getContextFactory().getContext();
                        logger.fine("Get KeyStoreService instance");
                        KeyStoreService kss = ctx.getServiceInstance(KeyStoreService.class);
                        logger.fine("Got KeyStoreService instance");

                        logger.fine("Get KeyStore instance: "+prop.getProperty("keystorestripe")+"/"+prop.getProperty("keystorename"));
                        ks = kss.getKeyStore(prop.getProperty("keystorestripe"), prop.getProperty("keystorename"), null);
                        logger.fine("Got KeyStore instance");

                    } catch (Exception e) {
                        logger.severe("Critical error. Unable to obtain a keystore instance: "+getStackTrace(e));
                    }
                    return "done";
                }
            });
            
            if (ks == null) {
                throw new Exception("Critical error. I could not obtain a keystore instance");
            } else {
                logger.fine("Succesfully used the KeyStoreService to obtained a KeyStore instance");
            }

            PasswordProtection pp = new PasswordProtection(prop.getProperty("keypassword").toCharArray());
            
            logger.fine("Trying to access keyalias (with predefined password): "+prop.getProperty("keyalias"));
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(prop.getProperty("keyalias"), pp);
            logger.fine("Keyalias succesfully accessed");

            logger.fine("Trying to get RSAPrivateKey from keyalias");
            RSAPrivateKey myPrivateKey = (RSAPrivateKey) pkEntry.getPrivateKey();
            logger.fine("Got RSAPrivateKey");
            logger.fine("Trying to get RSAPublicKey from keyalias");
            RSAPublicKey myPublicKey = (RSAPublicKey) pkEntry.getCertificate().getPublicKey();
            logger.fine("Got RSAPublicKey");

            logger.fine("Creating RSAKey with keyID(=keypairalias to be used by the recipient): "+prop.getProperty("keyalias"));
            // RSA signatures require a public and private RSA key pair, the public key
            // must be made known to the JWS recipient in order to verify the signatures
            //RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("ThisIsALongKeyThing").generate();
            RSAKey rsaJWK = new RSAKey.Builder(myPublicKey).privateKey(myPrivateKey)
                                                           .keyID(prop.getProperty("keyalias"))
                                                           .build();
            logger.fine("Created RSAKey");
            
            logger.fine("Creating JWSSigner with RSAKey");
            // Create RSA-signer with the private key
            JWSSigner signer = new RSASSASigner(rsaJWK);
            logger.fine("JWSSigner created");

            // Prepare JWT with claims set
            Date now = new Date();
            expirytime = Long.parseLong(prop.getProperty("tokenexpiry"));
            logger.fine("Token set to expire in: "+expirytime.toString());
            Date expires = new Date(now.getTime() + expirytime);
            logger.fine("Now: "+now+" Expires: "+expires);
            
            logger.fine("Creating claimsSet: subject ("+user+"), issuer ("+prop.getProperty("tokenissuer")+"), expirationtime ("+expires.toString()+"),issuetime ("+now.toString()+")");
            
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(user)
                                                               .issuer(prop.getProperty("tokenissuer"))
                                                               .expirationTime(expires)
                                                               .issueTime(new Date(new Date().getTime()))
                                                               .build();
            logger.fine("ClaimsSet created");

            logger.fine("Creating instance of token to be signed");
            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSet);
            logger.fine("Instance created");

            // Compute the RSA signature
            logger.fine("Signing the JWT token");
            signedJWT.sign(signer);
            logger.fine("Completed signing");

            // To serialize to compact form, produces something like
            // eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
            // mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
            // maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
            // -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
            logger.fine("Serializing the signed JWT token");
            token = signedJWT.serialize();
            logger.fine("Completed serializing");
        } catch (Exception e) {
            logger.severe("Unexpected error encountered. Return empty token: "+getStackTrace(e));
            token = "";
        }
        output = String.format("{ \"access_token\" : \"%s\",\n" + "  \"scope\"        : \"read write\",\n" +
                          "  \"token_type\"   : \"Bearer\",\n" + "  \"expires_in\"   : %s\n}", token,expirytime);

        logger.finer("Returning token: " + output);
        return output;
    }

    private static String getStackTrace(Throwable e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }
    
    private String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is,"UTF-8").useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

}
