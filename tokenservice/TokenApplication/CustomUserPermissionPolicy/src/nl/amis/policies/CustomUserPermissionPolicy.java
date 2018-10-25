package nl.amis.policies;

import java.security.Principal;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;

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

import org.glassfish.jersey.server.ContainerResponse;

public class CustomUserPermissionPolicy extends AssertionExecutor {

    private static ADFLogger logger = ADFLogger.createADFLogger(CustomUserPermissionPolicy.class);

    public CustomUserPermissionPolicy() {
        super();
    }

    @Override
    public IResult execute(IContext Context) throws WSMException {
        logger.info("Request received");
        logger.fine("Context is of class: " + Context.getClass().getName());
        Set<String> principles = new HashSet<String>();
        IResult result = new Result();

        try {
            //Retrieve Policy bindings from Policy File
            IAssertionBindings bindings = ((SimpleAssertion) (this.assertion)).getBindings();
            //Get Policy Config name from Policy File
            IConfig config = bindings.getConfigs().get(0);
            //Get Property set name of policy
            IPropertySet propertyset = config.getPropertySets().get(0);
            String valid_principles = propertyset.getPropertyByName("valid_principles").getValue();
            logger.fine("Valid principles: " + valid_principles);

            RESTHttpMessageContext messageContext = (RESTHttpMessageContext) Context;
            logger.fine("MessageContext properties: " + messageContext.getAllProperties().toString());

            //same way as below can be used to fetch the ContainerRequest which containt HTTP headers
            ContainerResponse containerResponse = (ContainerResponse) messageContext.getProperty("oracle.wsm.rest.response.context");

            if (containerResponse == null) {
                logger.fine("containerResponse is null so processing request and checking subject");
                Object subject = messageContext.getProperty("oracle.integration.platform.common.subject");
                if (subject == null) {
                    logger.info("Subject is null -> no authenticated user!");
                } else {
                    logger.info("Subject is not null. Adding principles from subject");
                    Subject mySubject = (Subject) subject;
                    for (Principal myPrinciple : mySubject.getPrincipals()) {
                        logger.fine("Adding principle: " + myPrinciple.getName());
                        principles.add(myPrinciple.getName());
                    }
                }

                String user_check_result = "";
                //Check valid users
                if (valid_principles != null && valid_principles.trim().length() > 0) {
                    String[] valid_principles_array = valid_principles.split(",");
                    Set<String> valid_principles_set = new HashSet<>(Arrays.asList(valid_principles_array));
                    valid_principles_set.forEach((principle) -> principle.trim());
                    valid_principles_set.retainAll(principles);
                    if (valid_principles_set.size() > 0) {
                        user_check_result = "valid";
                    } else {
                        user_check_result = "not valid";
                    }
                } else {
                    user_check_result = "not checked";
                }

                logger.info("User check result: " + user_check_result);

                if (user_check_result.equals("valid") || (user_check_result.equals("not checked"))) {
                    result.setStatus(IResult.SUCCEEDED);
                } else {
                    result.setStatus(IResult.FAILED);
                    result.setFault(new WSMException(WSMException.FAULT_FAILED_CHECK));
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
            logger.info("Request completed with: " + resultString);
            return result;
        } catch (Exception e) {
            logger.severe("Request not completed", e);
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
