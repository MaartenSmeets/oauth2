package nl.amis.policies;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetailsVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import java.util.List;

import java.util.Set;

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

public class ValidateTokenPolicy extends AssertionExecutor {

    private static ADFLogger logger = ADFLogger.createADFLogger(ValidateTokenPolicy.class);

    public ValidateTokenPolicy() {
        super();
    }

    private String getProperty(IPropertySet propertyset, String propertyname) {
        String result = propertyset.getPropertyByName(propertyname).getValue();
        if (result == null) {
            logger.warning("Property " + propertyname + " is null!");
        } else {
            if (result.length() == 0) {
                logger.warning("Property " + propertyname + " is empty!");
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
                HttpServletRequest request =
                    (HttpServletRequest) messageContext.getProperty(IMessageContext.HTTP_SERVLET_REQUEST);
                if (request != null) {
                    if (request.getHeader("Authorization") != null) {
                        JWTToken = request.getHeader("Authorization").replace("Bearer ", "");
                        logger.fine("Obtained JWT token: " + JWTToken);
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
                
                JWSObject jwsObject = JWSObject.parse(JWTToken);
                JWTClaimsSet claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
                
                try {
                    //Expected audience, iat, exp, nbt check
                    String expected_audience = this.getProperty(propertyset, "expected_audience");
                    List<String> expected_audience_list = new ArrayList<String>();
                    if (expected_audience != null) {
                        expected_audience_list = Arrays.asList((expected_audience.split(",")));
                        Set<String> expected_audience_stringset = new HashSet<String>(expected_audience_list);
                        Set<Audience> expected_audience_set = new HashSet<Audience>();
                        for (String aud : expected_audience_stringset) {
                            expected_audience_set.add(new Audience(aud));
                        }
                        JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(expected_audience_set);
                        verifier.verify(claims);
                        logger.info("JWT Token claimsset audience, expiration time, not before time verification success");
                    } else {
                        throw new BadJWTException("Expected audience has not been supplied in the policy configuration");
                    }
                    //Trusted issuers check
                    String trusted_issuers = this.getProperty(propertyset, "trusted_issuers");
                    List<String> trusted_issuers_list = new ArrayList<String>();
                    if (trusted_issuers != null) {
                        trusted_issuers_list = Arrays.asList(trusted_issuers.split(","));
                        if (trusted_issuers_list.contains(claims.getIssuer())) {
                            logger.info("JWT Token claimsset issuer verification success");
                        } else {
                            logger.warning("JWT Token claimsset issuer verification failed! " + claims.getIssuer() +
                                           " not present in " + trusted_issuers);
                            throw new BadJWTException(claims.getIssuer() + " not present in " + trusted_issuers);
                        }
                    } else {
                        throw new BadJWTException("Trusted issuers have not been supplied in the policy configuration!");
                    }
                } catch (BadJWTException e) {
                    logger.warning("JWT Token claimsset verification failed: " + e.getMessage());
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
