using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json;

namespace NexShopAPI.Middleware
{
    public class GlobalExceptionHandlerMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            try
            {
                await next(context);

            }catch (Exception ex)
            {
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

                ProblemDetails problem = new()
                {
                    Title = "An error occured",
                    Type = ex.GetType().Name,
                    Status = 500,
                    Detail = "Error. " + ex.Message
                };

                string json = JsonSerializer.Serialize(problem);
                

                /*string json = JsonSerializer.Serialize(
                    new
                    {
                        error = ex.GetType().Name,
                    }
                    );
                */

                context.Response.ContentType = "application/json";

                await context.Response.WriteAsync(json);

                
            }
        }
    }
}
