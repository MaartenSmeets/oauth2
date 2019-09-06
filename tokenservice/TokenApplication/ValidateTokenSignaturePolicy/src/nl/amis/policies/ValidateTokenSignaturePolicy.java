package nl.amis.policies;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import java.io.File;
import java.io.FileInputStream;

import java.security.KeyStore;
import java.security.interfaces.RSAPublicKey;

import javax.servlet.http.HttpServletRequest;

import oracle.adf.share.logging.ADFLogger;

import oracle.wsm.common.sdk.IContext;
import oracle.wsm.common.sdk.IMessageContext;
import oracle.wsm.common.sdk.IResult;
import oracle.wsm.common.sdk.MessageContext;
import oracle.wsm.common.sdk.Result;
import oracle.wsm.common.sdk.WSMException;
import oracle.wsm.policy.model.IAssertion;
import oracle.wsm.policy.model.IAssertionBindings;
import oracle.wsm.policy.model.IConfig;
import oracle.wsm.policy.model.IPropertySet;
import oracle.wsm.policy.model.ISimpleOracleAssertion;
import oracle.wsm.policy.model.impl.SimpleAssertion;
import oracle.wsm.policyengine.IExecutionContext;
import oracle.wsm.policyengine.impl.AssertionExecutor;

public class ValidateTokenSignaturePolicy extends AssertionExecutor {

    private static ADFLogger logger = ADFLogger.createADFLogger(ValidateTokenSignaturePolicy.class);

    public ValidateTokenSignaturePolicy() {
        super();
    }

    private String getProperty(IPropertySet propertyset,String propertyname) {
        String result = propertyset.getPropertyByName(propertyname).getValue();
        if (result == null) {
            logger.warning("Property "+propertyname+" is null!");
        } else {
            if (result.length()==0) {
                logger.warning("Property "+propertyname+" is empty!");
            }
        }
        return result;
    }

    @Override
    public IResult execute(IContext Context) throws WSMException {
        logger.info("Policy execution started");
        IResult result = new Result();

        try {
            MessageContext messageContext = (MessageContext) Context;
            if (messageContext.getStage() == IMessageContext.STAGE.request) {
                String JWTToken = "";
                // based on https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-rsa-signature
                HttpServletRequest request = (HttpServletRequest) messageContext.getProperty(IMessageContext.HTTP_SERVLET_REQUEST);
                if (request != null) {
                    if (request.getHeader("Authorization") != null) {
                        JWTToken = request.getHeader("Authorization").replace("Bearer ", "");
                        logger.fine("Obtained JWT token: "+JWTToken);
                    } else {
                        logger.warning("Authorization header is null!");
                    }
                } else {
                    logger.warning("HttpServletRequest is null!");
                }
                
                //Retrieve Policy bindings from Policy File
                IAssertionBindings bindings = ((SimpleAssertion) (this.assertion)).getBindings();
                //Get Policy Config name from Policy File
                IConfig config = bindings.getConfigs().get(0);
                //Get Property set name of policy
                IPropertySet propertyset = config.getPropertySets().get(0);
                String jks_location = this.getProperty(propertyset,"jks_location");
                String jks_password = this.getProperty(propertyset,"jks_password");
                String jks_keyalias = this.getProperty(propertyset,"jks_keyalias");
                KeyStore ks = KeyStore.getInstance("JKS");
                char[] pwdArrayKS = jks_password.toCharArray();
                if (!(new File(jks_location).isFile())) {
                    logger.warning("JKS file at location: "+jks_location+" does not exist");
                }
                ks.load(new FileInputStream(jks_location), pwdArrayKS);
                RSAPublicKey publicKey = (RSAPublicKey) ks.getCertificate(jks_keyalias).getPublicKey();
               
                JWSObject jwsObject = JWSObject.parse(JWTToken);
                JWSVerifier verifier = new RSASSAVerifier(publicKey);

                if (jwsObject.verify(verifier)) {
                    logger.info("JWT Token signature verification succeeded!");
                    result.setStatus(IResult.SUCCEEDED);
                } else {
                    logger.warning("JWT Token signature verification failed!");
                    result.setStatus(IResult.FAILED);
                }
            } else {
                logger.info("Processing response. No check required");
                result.setStatus(IResult.SUCCEEDED);
            }

            String resultString;
            switch (result.getStatus()) {
            case IResult.SUCCEEDED:
                resultString = "SUCCEEDED";
                break;
            case IResult.FAILED:
                resultString = "FAILED";
                break;
            case IResult.SUSPENDED:
                resultString = "SUSPENDED";
                break;
            case IResult.SKIP:
                resultString = "SKIP";
                break;
            default:
                resultString = "Unknown";
                break;
            }
            logger.info("Policy execution ended with: " + resultString);
            return result;
        } catch (Exception e) {
            logger.severe("Policy execution failed: ", e);
            throw new WSMException(WSMException.FAULT_FAILED_CHECK, e);
        }
    }
    //The init() method is invoked by the OWSM framework whenever the configuration of the policy attachment is updated (i.e. its property values are changed).
    @Override
    public void init(IAssertion assertion, IExecutionContext econtext, IContext Context) throws WSMException {
        this.assertion = assertion;
        this.econtext = econtext;
        logger.info("init is called. Policy configuration updated");
    }

    public oracle.wsm.policyengine.IExecutionContext getExecutionContext() {
        logger.fine("getExecutionContext is called");
        return this.econtext;
    }

    public boolean isAssertionEnabled() {
        //return policy enforce value
        logger.fine("isAssertionEnabled is called");
        return ((ISimpleOracleAssertion) this.assertion).isEnforced();
    }

    public String getAssertionName() {
        logger.fine("getAssertionName is called");
        return this.assertion
                   .getQName()
                   .toString();
    }

    @Override
    public void destroy() {
        logger.fine("destroy is called");
    }

    public oracle.wsm.common.sdk.IResult postExecute(oracle.wsm.common.sdk.IContext p1) {
        logger.fine("postExecute is called");
        IResult result = new Result();
        result.setStatus(IResult.SUCCEEDED);
        return result;
    }

}
