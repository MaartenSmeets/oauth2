package nl.amis.policies;

import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import oracle.adf.share.logging.ADFLogger;

import oracle.wsm.common.sdk.IContext;
import oracle.wsm.common.sdk.IResult;
import oracle.wsm.common.sdk.RESTHttpMessageContext;
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

import org.glassfish.jersey.server.ContainerRequest;

public class CustomUserPermissionPolicy extends AssertionExecutor {
    private ScriptEngine engine;

    public void initEngine() {
        ScriptEngineManager sem = new ScriptEngineManager();
        this.engine = sem.getEngineByName("javascript");
    }

    private static ADFLogger logger = ADFLogger.createADFLogger(CustomUserPermissionPolicy.class);

    public CustomUserPermissionPolicy() {
        super();
        initEngine();
    }

    @Override
    public IResult execute(IContext Context) throws WSMException {
        logger.info("Request received");
        logger.info("Context is of class: "+Context.getClass().getName());
        String request_user_name = "";
        try {
            //Retrieve Policy bindings from Policy File
            IAssertionBindings bindings = ((SimpleAssertion) (this.assertion)).getBindings();
            //Get Policy Config name from Policy File
            IConfig config = bindings.getConfigs().get(0);
            //Get Property set name of policy
            IPropertySet propertyset = config.getPropertySets().get(0);
            String valid_users = propertyset.getPropertyByName("valid_users").getValue();
            logger.info("Valid users: "+valid_users);
            
            RESTHttpMessageContext messageContext = (RESTHttpMessageContext) Context;
            logger.info("MessageContext properties: "+messageContext.getAllProperties().toString());

            ContainerRequest containerRequest = (ContainerRequest) messageContext.getProperty("oracle.wsm.rest.request.context");
            logger.info("Obtained containerRequest");
            IResult result = new Result();
            
            if (containerRequest == null) {
                logger.info("containerRequest is null!");
                result.setStatus(IResult.FAILED);
                result.setFault(new WSMException(WSMException.FAULT_FAILED_CHECK));
            } else {
                logger.fine("containerRequest headers");
                for (String propName : containerRequest.getHeaders().keySet()) {
                    logger.fine("Header: "+propName+" value: "+containerRequest.getHeaderString(propName));
                }
                
                logger.info("Parsing Authorization header");
                String JWTToken = containerRequest.getHeaderString("Authorization");
                logger.info("Parsing Authorization header: "+JWTToken);
                String[] JWTparts = JWTToken.split(Pattern.quote("."));
                logger.info("Split token in parts: "+Integer.toString(JWTparts.length));
                String JWTbody=JWTparts[1];
                logger.info("JWT body: "+JWTbody);
                String JWTbodyDecoded = new String(Base64.getDecoder().decode(JWTbody));
                logger.info("Obtained decoded JWT body");
                String script = "Java.asJSONCompatible(" + JWTbodyDecoded + ")";
                Object JSresult = this.engine.eval(script);
                Map contents = (Map) JSresult;
                logger.info("Obtained JSON map of size: "+Integer.toString(contents.size()));
                request_user_name = contents.get("sub").toString();
                logger.info("Obtained user name: "+request_user_name);
            }

            String user_check_result="";
            //Check valid users
            if (valid_users != null && valid_users.trim().length() > 0) {
                String[] valid_users_array = valid_users.split(",");
                boolean isPresent = false;
                logger.info("Checking valid users");
                for (String valid_user : valid_users_array) {
                    if (request_user_name.equals(valid_user.trim())) {
                        isPresent = true;
                        logger.info("User is in list of valid users");
                    }
                }
                
                if (isPresent) {
                    user_check_result = "valid";
                    
                } else {
                    user_check_result = "not valid";
                }
            } else {
                user_check_result = "not checked";
            }
            
            logger.info("User check result: "+user_check_result);

            // valid results: 
            // - one of them is valid
            // - both of them have not been checked
            if (user_check_result.equals("valid") || (user_check_result.equals("not checked"))) {
                result.setStatus(IResult.SUCCEEDED);
            } else {
                result.setStatus(IResult.FAILED);
                result.setFault(new WSMException(WSMException.FAULT_FAILED_CHECK));
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
            logger.info("Request completed with: " + resultString);
            return result;
        } catch (Exception e) {
            logger.severe("Request not completed",e);
            throw new WSMException(WSMException.FAULT_FAILED_CHECK, e);
        }
    }
    //The init() method is invoked by the OWSM framework whenever the configuration of the policy attachment is updated (i.e. its property values are changed).
    @Override
    public void init(IAssertion assertion, IExecutionContext econtext, IContext Context) throws WSMException {
        this.assertion = assertion;
        this.econtext = econtext;

    }

    public oracle.wsm.policyengine.IExecutionContext getExecutionContext() {
        return this.econtext;
    }

    public boolean isAssertionEnabled() {
        //return policy enforce value
        return ((ISimpleOracleAssertion) this.assertion).isEnforced();
    }

    public String getAssertionName() {
        return this.assertion
                   .getQName()
                   .toString();
    }

    @Override
    public void destroy() {
    }

    public oracle.wsm.common.sdk.IResult postExecute(oracle.wsm.common.sdk.IContext p1) {
        IResult result = new Result();
        result.setStatus(IResult.SUCCEEDED);
        return result;
    }

}
