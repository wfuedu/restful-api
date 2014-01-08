/* ***************************************************************************
 * Copyright 2013 Ellucian Company L.P. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/

package net.hedtech.restfulapi

import grails.converters.JSON
import grails.converters.XML
import grails.validation.ValidationException

import java.security.*

import static java.util.UUID.randomUUID

import javax.annotation.PostConstruct

import net.hedtech.restfulapi.marshallers.StreamWrapper

import net.hedtech.restfulapi.config.*

import net.hedtech.restfulapi.extractors.*
import net.hedtech.restfulapi.extractors.configuration.*

import org.codehaus.groovy.grails.web.json.JSONArray
import org.codehaus.groovy.grails.web.json.JSONElement
import org.codehaus.groovy.grails.web.json.JSONObject

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.InitializingBean
import org.springframework.dao.OptimisticLockingFailureException

import org.codehaus.groovy.grails.web.converters.configuration.ConvertersConfigurationHolder
import org.codehaus.groovy.grails.web.converters.configuration.ConverterConfiguration
import org.codehaus.groovy.grails.web.converters.configuration.DefaultConverterConfiguration
import org.codehaus.groovy.grails.web.converters.marshaller.ObjectMarshaller
import org.codehaus.groovy.grails.web.converters.Converter
import org.codehaus.groovy.grails.web.converters.configuration.ChainedConverterConfiguration
import org.codehaus.groovy.grails.web.converters.exceptions.ConverterException

import org.codehaus.groovy.grails.web.servlet.HttpHeaders

import org.codehaus.groovy.grails.web.servlet.GrailsApplicationAttributes
import org.apache.commons.logging.LogFactory

import edu.wfu.directory.DirectoryService


/**
 * A Restful API controller.
 * This controller delegates to a transactional service
 * corresponding to the resource (via naming convention or
 * configuration) based on the pluralized resource name
 * identified on the URL. This controller may be subclassed
 * to create stateless resource-specific controllers when
 * necessary.  (If a stateful controller is needed, this
 * should not be used as a base class.)
 **/
class RestfulApiController {

    // Because this controller is stateless, a single instance
    // may be used to handle all requests.
    //
    static scope = "singleton"

    private mediaTypeParser = new MediaTypeParser()

    def authenticationService

    def directoryService

    def authService

    private RestConfig restConfig

    private messageLog = LogFactory.getLog( 'RestfulApiController_messageLog' )

    private static final String RESPONSE_REPRESENTATION = 'net.hedtech.restfulapi.RestfulApiController.response_representation'

    // The default adapter simply passes through the method invocations to the service.
    //
    private RestfulServiceAdapter defaultServiceAdapter =
        [ list:   { def service, Map params                      -> service.list(params) },
          count:  { def service, Map params                      -> service.count(params) },
          show:   { def service, Map params                      -> service.show(params) },
          create: { def service, Map content, Map params         -> service.create(content, params) },
          update: { def service, def id, Map content, Map params -> service.update(id, content, params) },
          delete: { def service, def id, Map content, Map params -> service.delete(id, content, params) }
        ] as RestfulServiceAdapter

    private ExtractorAdapter extractorAdapter = new DefaultExtractorAdapter()

    // Custom headers (configured within Config.groovy)
    String totalCountHeader
    String pageMaxHeader
    String pageOffsetHeader
    String messageHeader
    String mediaTypeHeader

    // Paging query parameter names (configured within Config.groovy)
    String pageMax
    String pageOffset

    private Class pagedResultListClazz


    /**
     * Initializes the controller by registering the configured marshallers.
     **/
    // NOTE: The timing of PostConstruct works only when running 'test-app'
    //       -- it does *not* work for 'run-app' or 'test-app functional:'.
    //       'init()' is invoked explicitly from RestfulApiGrailsPlugin.
    // @PostConstruct
    void init() {

        totalCountHeader = grailsApplication.config.restfulApi.header.totalCount
        pageMaxHeader    = grailsApplication.config.restfulApi.header.pageMaxSize
        pageOffsetHeader = grailsApplication.config.restfulApi.header.pageOffset
        messageHeader    = grailsApplication.config.restfulApi.header.message
        mediaTypeHeader  = grailsApplication.config.restfulApi.header.mediaType

        pageMax    = grailsApplication.config.restfulApi.page.max
        pageOffset = grailsApplication.config.restfulApi.page.offset

        log.trace 'Initializing RestfulApiController...'
        JSON.createNamedConfig('restapi-error:json') { }
        XML.createNamedConfig('restapi-error:xml') { }

        if (!(grailsApplication.config.restfulApiConfig instanceof Closure)) {
            log.warn( "No restfulApiConfig defined in configuration.  No resources will be exposed.")
        } else {
            restConfig = RestConfig.parse( grailsApplication, grailsApplication.config.restfulApiConfig )
            restConfig.validate()

            restConfig.resources.values().each() { resource ->
                resource.representations.values().each() { representation ->
                    def framework = representation.resolveMarshallerFramework()
                    switch(framework) {
                        case ~/json/:
                            JSON.createNamedConfig("restfulapi:" + resource.name + ":" + representation.mediaType) { json ->
                                log.trace "Creating named config: 'restfulapi:${resource.name}:${representation.mediaType}'"
                                representation.marshallers.each() {
                                    log.trace "    ...registering json marshaller ${it.instance}"
                                    json.registerObjectMarshaller(it.instance,it.priority)
                                }
                            }
                        break
                        case ~/xml/:
                            XML.createNamedConfig("restfulapi:" + resource.name + ":" + representation.mediaType) { xml ->
                                representation.marshallers.each() {
                                    log.trace "    ...registering xml marshaller ${it.instance}"
                                    xml.registerObjectMarshaller(it.instance,it.priority)
                                }
                            }
                        break
                        default:
                            break
                    }
                    //register the extractor (if any)
                    if (null != representation.extractor) {
                        ExtractorConfigurationHolder.registerExtractor(resource.name, representation.mediaType, representation.extractor )
                    }
                }
            }
        }

        //see if we are running with hibernate and need to support PagedList
        //as of grails 2.3, this class is in the hibernate plugin, not
        //core, and we don't want direct hibernate dependencies
        try {
            pagedResultListClazz = Class.forName('grails.orm.PagedResultList')
        } catch (ClassNotFoundException) {
            //not using hibernate support
        }


        log.trace 'Done initializing RestfulApiController...'
    }


// ---------------------------------- ACTIONS ---------------------------------


    // GET /api/pluralizedResourceName
    //
    public def list() {

        log.trace "list invoked for ${params.pluralizedResourceName}"
        try {
            checkMethod( Methods.LIST )
            def responseRepresentation = getResponseRepresentation() // adds representation attribute to request

            def requestParams = params  // accessible from within withCacheHeaders
            def logger = log            // ditto

            if (request.method == "POST") {
                def queryCriteria = parseRequestContent( request, 'query-filters' )
                updatePagingQueryParams( queryCriteria ) // We'll ensure params uses expected Grails naming...
                requestParams << queryCriteria
            }
            else {
                updatePagingQueryParams( requestParams ) // We'll ensure params uses expected Grails naming...
            }

            def service = getService()
            def delegateToService = getServiceAdapter()
            logger.trace "... will delegate list() to service $service using adapter $delegateToService"

            def result = delegateToService.list(service, requestParams)
            logger.trace "... service returned $result"

            def count
            if ((null != pagedResultListClazz) && (pagedResultListClazz.isInstance(result))) {
                count = result.totalCount
            } else if (result instanceof PagedResultList) {
                count = result.getTotalCount()
            } else {
                count = delegateToService.count(service, requestParams)
            }

            // Need to create etagValue outside of 'etag' block:
            // http://jira.grails.org/browse/GPCACHEHEADERS-14
            String etagValue = shaFor( result, count, responseRepresentation.mediaType )

            withCacheHeaders {
                etag {
                    etagValue
                }
                delegate.lastModified {
                    lastModifiedFor( result )
                }
                generate {
                    ResponseHolder holder = new ResponseHolder()
                    holder.data = result
                    holder.addHeader(totalCountHeader, count)
                    holder.addHeader(pageOffsetHeader, requestParams.offset ? requestParams?.offset : 0)
                    holder.addHeader(pageMaxHeader, requestParams.max ? requestParams?.max : result.size())
                    renderSuccessResponse( holder, 'default.rest.list.message' )
                }
            }
        }
        catch (e) {
            messageLog.error "Caught exception ${e.message}", e
            renderErrorResponse(e)
            return
        }
    }


    // GET /api/pluralizedResourceName/id
    //
    public def show() {
        log.trace "show() invoked for ${params.pluralizedResourceName}/${params.id}"
        try {
            checkMethod( Methods.SHOW )
            def responseRepresentation = getResponseRepresentation()

            def requestParams = params  // accessible from within withCacheHeaders
            def logger = log            // ditto

            def result = getServiceAdapter().show( getService(), requestParams )
            // Need to create etagValue outside of 'etag' block:
            // http://jira.grails.org/browse/GPCACHEHEADERS-14
            String etagValue = shaFor( result, responseRepresentation.mediaType )

            withCacheHeaders {

                etag {
                    etagValue
                }
                delegate.lastModified {
                    if (hasProperty( result, "lastUpdated" ))       result.lastUpdated
                    else if (hasProperty( result, "lastModified" )) result.lastModified
                    else                                            new Date()
                }
                generate {
                    renderSuccessResponse( new ResponseHolder( data: result ),
                                           'default.rest.shown.message' )
                }
            }
        }
        catch (e) {
            messageLog.error "Caught exception ${e.message}", e
            renderErrorResponse(e)
        }
    }


    // POST /api/pluralizedResourceName
    //
    public def create() {
        log.trace "create() invoked for ${params.pluralizedResourceName}"
        def result

        try {
            checkMethod( Methods.CREATE )
            def content = parseRequestContent( request )
            log.trace "Extracted content $content"
            getResponseRepresentation()
            result = getServiceAdapter().create( getService(), content, params )
            response.setStatus( 201 )
            renderSuccessResponse( new ResponseHolder( data: result ),
                                   'default.rest.created.message' )
        }
        catch (e) {
            messageLog.error "Caught exception ${e.message}", e
            renderErrorResponse(e)
        }
    }


    // PUT/PATCH /api/pluralizedResourceName/id
    //
    public def update() {
        log.trace "update() invoked for ${params.pluralizedResourceName}/${params.id}"
        def result

        try {
            checkMethod( Methods.UPDATE )
            def content = parseRequestContent( request )
            if (content && content.id && content.id != params.id) {
                throw new IdMismatchException( params.pluralizedResourceName )
            }

            getResponseRepresentation()
            result = getServiceAdapter().update( getService(), params.id, content, params )
            response.setStatus( 200 )
            renderSuccessResponse( new ResponseHolder( data: result ),
                                   'default.rest.updated.message' )
        }
        catch (e) {
            messageLog.error "Caught exception ${e.message}", e
            renderErrorResponse(e)
        }
    }


    // DELETE /api/pluralizedResourceName/id
    //
    public def delete() {
        log.trace "delete() invoked for ${params.pluralizedResourceName}/${params.id}"
        try {
            checkMethod( Methods.DELETE )
            def content = [:]
            //Using angular in some browsers causes the Content-Type header
            //to be set as application/xml or some other default for zero-length
            //bodies, instead of a configured type.
            //If we have a delete with a zero-length body,
            //we will skip parsing the request content and use an
            //empty map.
            if (request.getContentLength() != 0) {
                content = parseRequestContent( request )
            }
            if (content && content.id && content.id != params.id) {
                throw new IdMismatchException( params.pluralizedResourceName )
            }
            getServiceAdapter().delete( getService(), params.id, content, params )
            response.setStatus( 200 )
            renderSuccessResponse( new ResponseHolder(), 'default.rest.deleted.message' )
        }
        catch (e) {
            messageLog.error "Caught exception ${e.message}", e
            renderErrorResponse(e)
        }
    }


// ---------------------------- Helper Methods -------------------------------


    /**
     * Renders a successful response using the supplied map and msg resource code.
     * A message property with a value translated from the message resource code
     * provided with a localized and singularized resource name will be automatically
     * added to the map.
     * @param responseMap the Map to render
     * @param msgResourceCode the resource code used to create a message entry
     **/
     protected void renderSuccessResponse(ResponseHolder holder, String msgResourceCode) {
        String localizedName = localize(Inflector.singularize(params.pluralizedResourceName))
        holder.message = message( code: msgResourceCode, args: [ localizedName ] )
        renderResponse( holder )
    }


    /**
     * Renders an error response appropriate for the exception.
     * @param e the exception to render an error response for
     **/
    protected void renderErrorResponse( Throwable e ) {
        ResponseHolder responseHolder = createErrorResponse( e )
        //The versioning applies to resource representations, not to
        //errors.  In fact, it can't, as the error may be that an unrecognized format
        //was requested.  So if we are returning an error response, we switch the format
        //to either json or xml.
        //So we will look at the Accept-Header directly and try to determine if JSON or XML was
        //requested.  If we can't decide, we will return JSON.
        String contentType = null
        def content
        MediaType[] acceptedTypes = mediaTypeParser.parse(request.getHeader(HttpHeaders.ACCEPT))
        def type = acceptedTypes.size() > 0 ? acceptedTypes[0].name : ""
        switch(type) {
            case ~/.*xml.*/:
                contentType = 'application/xml'
                if (responseHolder.data != null) {
                    useXML("restapi-error:xml") {
                        content = responseHolder.data as XML
                    }
                }
            break
            default:
                contentType = 'application/json'
                if (responseHolder.data != null) {
                    useJSON("restapi-error:json") {
                        content = responseHolder.data as JSON
                    }
                }
            break
        }

        responseHolder.headers.each { header ->
            header.value.each() { val ->
                response.addHeader( header.key, val )
            }
        }
        if (responseHolder.message) {
            response.addHeader( messageHeader, responseHolder.message )
        }
        render(text: content ? content : "", contentType: contentType )
    }


    protected ResponseHolder createErrorResponse( Throwable e ) {
        ResponseHolder responseHolder = new ResponseHolder()
        try {
            def handler = exceptionHandlers[ getErrorType( e ) ]
            if (!handler) {
                handler = exceptionHandlers[ 'AnyOtherException' ]
            }
            def result = handler(params.pluralizedResourceName, e)
            if (result.headers) {
                result.headers.each() { header ->
                    if (header.value instanceof Collection) {
                        header.value.each { val ->
                            responseHolder.addHeader( header.key, val )
                        }
                    } else {
                        responseHolder.addHeader( header.key, header.value )
                    }
                }
            }
            responseHolder.data = result.returnMap
            responseHolder.message = result.message
            this.response.setStatus( result.httpStatusCode )
        }
        catch (t) {
            //We generated an exception trying to generate an error response.
            //Log the error, and attempt to fall back on a generic fail-whale response
            log.error( "Caught exception attemping to prepare an error response: ${t.message}", t )
            responseHolder.data = null

            responseHolder.message = message( code: 'default.rest.unexpected.exception.messages' )
            this.response.setStatus( 500 )
        }
        return responseHolder
    }


    protected String selectContentTypeForResponse( RepresentationConfig representation ) {
        def result = representation.contentType
        if (null == result) {
            switch(representation.mediaType) {
                case ~/.*json$/:
                    result = 'application/json'
                    break
                case ~/.*xml$/:
                    result = 'application/xml'
                    break
                default:
                    result = representation.mediaType
                    break
            }
        }
        result
    }


    protected def generateResponseContent( RepresentationConfig representation, def data ) {
        def result
        def framework = representation.resolveMarshallerFramework()

        if (null == framework) {
            //if we can't determine a framework by this point,
            //we have no idea how to marshall a response.
            //note that this should never happen, as we should
            //have checked for this before ever delegating to a service
            unsupportedResponseRepresentation()
        }

        switch(framework) {
            case ~/json/:
                log.trace "Going to useJSON with representation $representation"
                useJSON(representation) {
                    result = (data as JSON) as String
                }
                break
            case ~/xml/:
                log.trace "Going to useXML with representation $representation"
                useXML(representation) {
                    result = (data as XML) as String
                }
                break
            default:
                log.trace "Going to use custom marshaller service $framework with representation $representation"
                def service = getMarshallingService(framework)
                result = service.marshalObject(data,representation)
                break
        }
        result
     }


    /**
     * Renders the content of the supplied map using a registered converter.
     * @param responseMap the Map containing the data and headers to render
     * @param format if specified, use the as the response format.  Otherwise
     *        use the format on the response (taken from the Accept-Header)
     * @param mediaType if specified, use as the media type for the response.
     *        Otherwise, use the media-type type specified by the Accept header.
     **/
    protected void renderResponse( ResponseHolder responseHolder ) {
        //def acceptedTypes = mediaTypeParser.parse( request.getHeader(HttpHeaders.ACCEPT) )
        def representation
        def content
        def contentType

        if (responseHolder.data != null) {
            representation = getResponseRepresentation()
            content = generateResponseContent( representation, responseHolder.data )
            contentType = selectContentTypeForResponse( representation )
        }

        if (content != null) {
            response.addHeader( mediaTypeHeader, representation.mediaType )
        }
        responseHolder.headers.each { header ->
            header.value.each() { val ->
                response.addHeader( header.key, val )
            }
        }
        if (responseHolder.message) {
            response.addHeader( messageHeader, responseHolder.message )
        }

        if (content != null) {
            if (content instanceof byte[]) {
                response.setContentType(contentType)
                response.setContentLength(content.length)
                def out = response.getOutputStream()
                out.write(content)
                out.flush()
                out.close()
            } else if (content instanceof InputStream) {
                response.setContentType(contentType)
                def out = response.getOutputStream()
                out << content
                out.flush()
                out.close()
            } else if (content instanceof StreamWrapper) {
                response.setContentType(contentType)
                response.setContentLength(content.totalSize)
                def out = response.getOutputStream()
                out << content.stream
                out.flush()
                out.close()
            } else {
                render(text: content, contentType: contentType )
            }
        } else {
            render(text:"", contentType:'text/plain')
        }
    }


    protected boolean hasProperty( Object obj, String name ) {
        obj.getMetaClass().hasProperty(obj, "$name") && obj."$name"
    }


    protected String shaFor( resourceModel, String requestedMediaType ) {
        MessageDigest digest = MessageDigest.getInstance( 'SHA1' )
        shaFor( resourceModel, digest, requestedMediaType )
    }


    protected String shaFor( resourceModel, MessageDigest digest, String requestedMediaType ) {

        digest.update( requestedMediaType.getBytes( 'UTF-8' ) )

        if (resourceModel.getMetaClass().respondsTo( resourceModel, "getEtag" )) {
            log.trace "Will create ETag based upon a model's 'getEtag()' method"
            digest.update( "${resourceModel.getEtag()}".getBytes( 'UTF-8' ) )
            return "\"${new BigInteger( 1, digest.digest() ).toString( 16 ).padLeft( 40,'0' )}\""
        }

        if (!hasProperty( resourceModel, "id" )) {
            log.trace "Cannot create ETag using a resource's identity, returning a UUID"
            return randomUUID() as String
        }
        digest.update( "${resourceModel.id}".getBytes( 'UTF-8' ) )

        // we'll require either version, lastModified, or (worst case) all properties
        boolean changeIndictorFound = false
        if (hasProperty( resourceModel, "version") ) {
            changeIndictorFound = true
            digest.update( "${resourceModel.version}".getBytes( 'UTF-8' ) )
        }
        else if (hasProperty( resourceModel, "lastUpdated" )) {
            changeIndictorFound = true
            digest.update( "${resourceModel.lastUpdated}".getBytes( 'UTF-8' ) )
        }
        else if (hasProperty( resourceModel, "lastModified" )) {
            changeIndictorFound = true
            digest.update( "${resourceModel.lastModified}".getBytes( 'UTF-8' ) )
        }

        if (changeIndictorFound) {
            log.trace "Returning an ETag based on id and a known change indicator"
            return "\"${new BigInteger( 1, digest.digest() ).toString( 16 ).padLeft( 40,'0' )}\""
        } else {
            // Note: we don't return empty ETags as doing so may cause some caching
            //       infrastructure to reset connections.
            log.trace "Cannot create ETag using a resource's change indicator, returning a UUID"
            return randomUUID() as String
        }
    }


    protected String shaFor( Collection resourceModels, long totalCount, String requestedMediaType ) {

        if (!(resourceModels && totalCount)) return ''
        MessageDigest digest = MessageDigest.getInstance( 'SHA1' )

        // we'll use the collection size, the totalCount of resources,
        // and the sha1 calculated for each item in the collection
        digest.update( "${resourceModels.size()}".getBytes( 'UTF-8' ) )
        digest.update( "${totalCount}".getBytes( 'UTF-8' ) )
        resourceModels.each {
            shaFor( it, digest, requestedMediaType )
        }
        "\"${new BigInteger( 1, digest.digest() ).toString( 16 ).padLeft( 40,'0' )}\""
    }


    protected Date lastModifiedFor( Collection resourceModels ) {

        if (!resourceModels) return new Date()

        Date latestDate
        resourceModels.each {
            if (hasProperty( it, 'lastUpdated' )) {
                if (it.lastUpdated > latestDate) latestDate = it.lastUpdated
            }
            else if (hasProperty( it, 'lastModified' )) {
                if (it.lastModified > latestDate) latestDate = it.lastModified
            }
        }
        latestDate ?: new Date()
        latestDate
    }


    /**
     * Parses the content from the request.
     * Returns a map representing the properties of content.
     * @param request the request containing the content
     **/
    protected Map parseRequestContent( request, String resource = params.pluralizedResourceName ) {
        MultiReadHttpServletRequestWrapper wrapper = new MultiReadHttpServletRequestWrapper(request)
        String signature = wrapper.getHeader("Signature")
        String data = wrapper.reader.text

        if(!authService.isDataAuthenticated(data,signature)){
            log.warn "Signature appears to be not valid: " + signature
            unauthorizedRequest()
        }

        ResourceConfig resourceConfig = getResourceConfig( resource )
        def representation = getRequestRepresentation( resource )

        Extractor extractor = ExtractorConfigurationHolder.getExtractor( resourceConfig.name, representation.mediaType )
        if (!extractor) {
            unsupportedRequestRepresentation()
        }
        getExtractorAdapter().extract(extractor, wrapper)
    }


    /**
     * Maps an exception to an error type known to the controller.
     * @param e the exception to map
     **/
    protected String getErrorType( e ) {

        if (e.metaClass.respondsTo( e, "getHttpStatusCode") &&
            e.hasProperty( "returnMap" ) &&
            e.returnMap && (e.returnMap instanceof Closure)) {
            //treat as an 'ApplicationException'.  That is, assume the exception is taking
            //responsibility for specifying the correct status code and
            //response message elements
            return 'ApplicationException'
        } else if (e instanceof OptimisticLockingFailureException) {
            return 'OptimisticLockException'
        } else if (e instanceof ValidationException) {
            return 'ValidationException'
        } else if (e instanceof UnsupportedResourceException) {
            return 'UnsupportedResourceException'
        } else if (e instanceof UnsupportedRequestRepresentationException) {
            return 'UnsupportedRequestRepresentationException'
        } else if (e instanceof UnsupportedResponseRepresentationException) {
            return 'UnsupportedResponseRepresentationException'
        } else if (e instanceof IdMismatchException) {
            return 'IdMismatchException'
        } else if (e instanceof UnsupportedMethodException) {
            return 'UnsupportedMethodException'
        } else {
            return 'AnyOtherException'
        }
    }


    /**
     * Returns the name of the service to which this controller will delegate.
     * This implementation assumes the resource is a Grails 'domain'
     * object, and that the service name can be constructed by using the pluralized
     * 'resource' name found on the URL and appending 'Service'.
     * For example: If a URL of /api/pluralizedResourceName/id was invoked,
     * a service name of 'SingularizedResourceNameService' will be returned.
     **/
    protected String getServiceName() {
        def svcName = getResourceConfig()?.serviceName
        if (svcName == null) {
            svcName = "${domainName()}Service"
        }
        log.trace "getServiceName() will return $svcName"
        svcName
    }


    /**
     * Returns the transactional service corresponding to this resource.
     * The default implementation assumes the resource is a Grails 'domain'
     * object, and that the service can be identified by using the pluralized
     * 'resource' name found on the URL.
     * For example: If a URL of /api/pluralizedResourceName/id was invoked,
     * a service named 'SingularizedResourceNameService' will be retrieved
     * from the IoC container.
     * @see #getServiceName()
     **/
    protected def getService() {
        def svc = getSpringBean( getServiceName() )
        log.trace "getService() will return service $svc"
        if (null == svc) {
            log.warn "No service found for resource ${params.pluralizedResourceName}"
            throw new UnsupportedResourceException(params.pluralizedResourceName)
        }
        log.trace "getService() will return service $svc"
        svc
    }


    protected def getMarshallingService(String name) {
        def svc = getSpringBean( name, true )
        log.trace "getMarshallingService() will return service $svc"
        svc
    }


    /**
     * Returns the name of the optional per-service adapter to use.
     * This implementation assumes the adapter is a spring bean
     * implementing the RestfulServiceAdapter interface.
     **/
    protected String getServiceAdapterName() {
        def name = getResourceConfig()?.serviceAdapterName
        log.trace "getServiceAdapterName() will return $name"
        name
    }


    /**
     * Returns an adapter supporting the service.
     * This will look for a service-specific adapter configured within the
     * 'restfulApiServiceAdapters' map (if registered in the Spring container).
     * Next, the restfulApiServiceAdapters map will be checked to see if an
     * adapter is registered for 'any' service.
     * If a service-specific adapter was not found, this method will look for a
     * 'global' adapter within the Spring container using the name 'restfulServiceAdapter'.
     * If no adapter is found in the Spring container, this
     * implementation will return a built-in pass-through adapter.
     **/
    protected RestfulServiceAdapter getServiceAdapter() {
        def adapter
        def adapterName = getServiceAdapterName()
        if (null != adapterName) {
            adapter = getSpringBean( getServiceAdapterName() )
            if (null == adapter) {
                //if we can't find the per-resource adapter that was configured,
                //do not continue.  The resource is not configured correctly and
                //cannot be supported.
                log.warn "Could not locate bean for ${adapterName} configured as the service adapter for resource ${params.pluralizedResourceName}; "
                throw new UnsupportedResourceException(params.pluralizedResourceName)
            }
        }

        // We'll see if there is a global adapter defined
        if (null == adapter) {
            adapter = getSpringBean( 'restfulServiceAdapter' )
        }

        //if no adapter, we'll use the default
        adapter = adapter ?: defaultServiceAdapter
        log.trace "getServiceAdapter() will return adapter $adapter"
        adapter
    }


    protected def getSpringBean( String beanName, boolean required = false ) {

        log.trace "Looking for a Spring bean named $beanName"
        def bean
        try {
            bean = applicationContext.getBean(beanName)
        } catch (e) { // it is not an error if we cannot find an adapter
            if (required) {
                log.error "Did not find a bean named $beanName - ${e.message}", e
                throw e
            } else {
                log.trace "Did not find a bean named $beanName - ${e.message}"
            }
        }
        bean
    }


    protected ExtractorAdapter getExtractorAdapter() {
        extractorAdapter
    }


    /**
     * Returns the best match, or null if no supported representation for the resource exists.
     **/
    protected RepresentationConfig getRepresentation(pluralizedResourceName, allowedTypes) {
        return restConfig.getRepresentation( pluralizedResourceName, allowedTypes.name )
    }


    protected void checkMethod( String method ) {
        def resource = getResourceConfig()
        if (!resource) {
            throw new UnsupportedResourceException( params.pluralizedResourceName )
        }
        if (!resource.allowsMethod( method ) ) {
            def allowed = resource.getMethods().intersect( Methods.getMethodGroup( method ) )
            throw new UnsupportedMethodException( supportedMethods:allowed )
        }
    }


    private void updatePagingQueryParams(requestParams) {
        if (pageMax != 'max' || pageOffset != 'offset') {
            if (requestParams."$pageMax")    requestParams.max = requestParams."$pageMax"
            if (requestParams."$pageOffset") requestParams.offset = requestParams."$pageOffset"
        }
    }


    private String localize(String name) {
        message( code: "${name}.label", default: "$name" )
    }


    private String domainName() {
        Inflector.asPropertyName(params.pluralizedResourceName)
    }


    /**
     * If we try to use an unknown configuration for a grails converter, a ConverterException
     * is thrown, which can't be programmatically distinguished from other marshalling errors.
     * So we'll test for the existence of the named configuration upfront, so if we don't
     * support it, we can return an appropriate error response.
     **/
    private Object useJSON( String config, Closure closure ) {
        try {
            JSON.getNamedConfig( config )
        } catch (ConverterException e) {
            //failure to retrieve the named config.  Treat as an unknown format.
            throw new UnsupportedResponseRepresentationException( params.pluralizedResourceName, request.getHeader(HttpHeaders.ACCEPT) )
        }
        JSON.use(config,closure)
    }


    private Object useJSON(RepresentationConfig config, Closure closure) {
        ResourceConfig resource = getResourceConfig()
        useJSON( "restfulapi:" + resource.name + ":" + config.mediaType, closure )
    }


    /**
     * If we try to use an unknown configuration for a grails converter, a ConverterException
     * is thrown, which can't be programmatically distinguished from other marshalling errors.
     * So we'll test for the existence of the named configuration upfront, so if we don't
     * support it, we can return an appropriate error response.
     **/
    private Object useXML( String config, Closure closure ) {
        try {
            XML.getNamedConfig( config )
        } catch (ConverterException e) {
            //failure to retrieve the named config.  Treat as an unknown format.
            throw new UnsupportedResponseRepresentationException( params.pluralizedResourceName, request.getHeader(HttpHeaders.ACCEPT) )
        }
        XML.use(config,closure)
    }


    private Object useXML( RepresentationConfig config, Closure closure ) {
        ResourceConfig resource = getResourceConfig()
        useXML( "restfulapi:" + resource.name + ":" + config.mediaType, closure )
    }


    private RepresentationConfig getResponseRepresentation() {
        def representation = request.getAttribute( RESPONSE_REPRESENTATION )
        if (representation == null) {
            def acceptedTypes = mediaTypeParser.parse( request.getHeader(HttpHeaders.ACCEPT) )
            representation = getRepresentation( params.pluralizedResourceName, acceptedTypes )
            if (representation == null || representation.resolveMarshallerFramework() == null) {
                //if no representation, or the representation does not have a marshaller framework,
                //then this is a representation that cannot be marshalled to.
                unsupportedResponseRepresentation()
            }
            request.setAttribute( RESPONSE_REPRESENTATION, representation )
        }
        representation
    }


    private RepresentationConfig getRequestRepresentation( String resource = params.pluralizedResourceName ) {
        def types = mediaTypeParser.parse( request.getHeader(HttpHeaders.CONTENT_TYPE) )
        def type = types.size() > 0 ? [types[0]] : []
        def representation = getRepresentation( resource, type )
        if (representation == null) {
            unsupportedRequestRepresentation()
        }
        return representation
    }


    private unsupportedResponseRepresentation() {
        throw new UnsupportedResponseRepresentationException( params.pluralizedResourceName, request.getHeader(HttpHeaders.ACCEPT) )
    }


    private unsupportedRequestRepresentation() {
        throw new UnsupportedRequestRepresentationException( params.pluralizedResourceName, request.getHeader(HttpHeaders.CONTENT_TYPE ) )
    }

    private unauthorizedRequest() {
        throw new UnauthorizedRequestException( request.getHeader('signature') )
    }


    private ResourceConfig getResourceConfig( String resource = params.pluralizedResourceName ) {
        restConfig.getResource( resource )
    }

    private def exceptionHandlers = [

        'ValidationException': { pluralizededResourceName, e->
            [
                httpStatusCode: 400,
                headers: ['X-Status-Reason':'Validation failed'],
                message: message( code: "default.rest.validation.errors.message",
                                          args: [ Inflector.singularize( pluralizededResourceName ) ] ) as String,
                returnMap: [
                    errors: [
                        [
                            type: "validation",
                            errorMessage: e.message
                        ]
                    ]
                ]
            ]
        },
        'OptimisticLockException': { pluralizededResourceName, e ->
            [
                httpStatusCode: 409,
                message: message( code: "default.optimistic.locking.failure",
                                          args: [ Inflector.singularize( pluralizededResourceName ) ] ) as String,
            ]
        },
        'UnsupportedResourceException': { pluralizededResourceName, e ->
            [
                httpStatusCode: 404,
                message: message( code: "default.rest.unknownresource.message",
                                          args: [ e.getPluralizedResourceName() ] ) as String,
            ]
        },
        'UnsupportedResponseRepresentationException': { pluralizededResourceName, e ->
            [
                httpStatusCode: 406,
                message: message( code: "default.rest.unknownrepresentation.message",
                                          args: [ e.getPluralizedResourceName(), e.getContentType() ] ) as String,
            ]
        },
        'UnsupportedRequestRepresentationException': { pluralizededResourceName, e ->
            [
                httpStatusCode: 415,
                message: message( code: "default.rest.unknownrepresentation.message",
                                          args: [ e.getPluralizedResourceName(), e.getContentType() ] ) as String,
            ]
        },
        'IdMismatchException': { pluralizededResourceName, e ->
            [
                httpStatusCode: 400,
                headers: ['X-Status-Reason':'Id mismatch'],
                message: message( code: "default.rest.idmismatch.message",
                                  args: [ e.getPluralizedResourceName() ] ) as String
            ]
        },
        'UnsupportedMethodException': { pluralizedResourceName, e ->
            def allowedHTTPMethods = []
            e.getSupportedMethods().each {
                allowedHTTPMethods.add( Methods.getHttpMethod( it ) )
            }
            def r = [
                httpStatusCode: 405,
                headers: ['Allow':allowedHTTPMethods],
                message: message( code: 'default.rest.method.not.allowed.message' ) as String
            ]
        },
        'ApplicationException': { pluralizededResourceName, e ->
            // wrap the 'message' invocation within a closure, so it can be
            // passed into an ApplicationException to localize error messages
            def localizer = { mapToLocalize ->
                this.message( mapToLocalize )
            }

            def map = [:]
            def appMap = e.returnMap( localizer )
            map.httpStatusCode = e.getHttpStatusCode()
            if (appMap.headers) {
                map.headers = appMap.headers
            }
            if (appMap.message) {
                map.message = appMap.message
            }

            def returnMap = [:]
            if (appMap.errors) {
                returnMap.errors = appMap.errors
            }
            map.returnMap = returnMap

            return map
        },
        // Catch-all.  Unknown exception type.
        'AnyOtherException': { pluralizededResourceName, e ->
            [
                httpStatusCode: 500,
                message: message( code: "default.rest.general.errors.message",
                                  args: [ pluralizededResourceName ] ) as String,
                returnMap: [
                    errors: [ [
                        type: "general",
                        errorMessage: e.message
                        ]
                    ]
                ]
            ]
        }
    ]

}
