package br.com.gruponeural.core.gateway.proxy;

import io.smallrye.common.annotation.RunOnVirtualThread;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

@Path("/")
@RunOnVirtualThread
public class GatewayProxyResource {

  @Inject
  GatewayProxyService proxyService;

  @GET
  @Path("{servico}/{path:.*}")
  @Produces(MediaType.WILDCARD)
  public Response get(
      @PathParam("servico") String servico,
      @PathParam("path") String path,
      @Context ContainerRequestContext requestContext,
      @Context UriInfo uriInfo) throws Exception {
    return proxyService.proxy("GET", servico, path, requestContext, uriInfo);
  }

  @POST
  @Path("{servico}/{path:.*}")
  @Consumes(MediaType.WILDCARD)
  @Produces(MediaType.WILDCARD)
  public Response post(
      @PathParam("servico") String servico,
      @PathParam("path") String path,
      @Context ContainerRequestContext requestContext,
      @Context UriInfo uriInfo) throws Exception {
    return proxyService.proxy("POST", servico, path, requestContext, uriInfo);
  }

  @PUT
  @Path("{servico}/{path:.*}")
  @Consumes(MediaType.WILDCARD)
  @Produces(MediaType.WILDCARD)
  public Response put(
      @PathParam("servico") String servico,
      @PathParam("path") String path,
      @Context ContainerRequestContext requestContext,
      @Context UriInfo uriInfo) throws Exception {
    return proxyService.proxy("PUT", servico, path, requestContext, uriInfo);
  }

  @DELETE
  @Path("{servico}/{path:.*}")
  @Produces(MediaType.WILDCARD)
  public Response delete(
      @PathParam("servico") String servico,
      @PathParam("path") String path,
      @Context ContainerRequestContext requestContext,
      @Context UriInfo uriInfo) throws Exception {
    return proxyService.proxy("DELETE", servico, path, requestContext, uriInfo);
  }

}
