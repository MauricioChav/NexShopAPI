using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using NexShopAPI.DataAccess.IOperations;
using NexShopAPI.DataAccess.Models;
using System.Data;
using System.Reflection;

namespace NexShopAPI.DataAccess.Operations
{
    public class ClientOperations : IClientOperation
    {
        //Connection and command
        SqlConnection conn = null;
        SqlCommand cmd = null;

        private readonly IConfiguration _config;
        private readonly string _connectionString;

        public ClientOperations(IConfiguration config)
        {
            _config = config;
            _connectionString = "DefaultConnection";
        }

        public async Task<List<Client>> GetAllClientsAsync()
        {
            List<Client> clients = new List<Client>();
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[csp_Get_Clients]";

                await conn.OpenAsync();

                SqlDataReader dr = await cmd.ExecuteReaderAsync();

                while (await dr.ReadAsync())
                {
                    //Create new element and asign every value with the info from the reader
                    Client client = new Client();
                    client.Id = Convert.ToInt32(dr["Id"]);
                    client.FirstName = dr["FirstName"].ToString();
                    client.LastName = dr["LastName"].ToString();
                    client.Email = dr["Email"].ToString();

                    //Verify if Birthday field is not null
                    if (dr["Birthday"] != DBNull.Value)
                    {
                        client.Birthday = Convert.ToDateTime(dr["Birthday"]).Date;
                    }
                    else
                    {
                        client.Birthday = null;
                    }

                    //Validate if AddressId is null
                    if (dr["AddressId"] != DBNull.Value)
                    {
                        client.AddressId = Convert.ToInt32(dr["AddressId"]);
                    }
                    else
                    {
                        client.AddressId = null;
                    }

                    clients.Add(client);
                }

                return clients;

            }
  
        }

        public async Task<Client> GetClientByIdAsync(int id)
        {
            Client client = new Client();
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[csp_Get_ClientId]";
                cmd.Parameters.AddWithValue("@Id", id);

                await conn.OpenAsync();

                SqlDataReader dr = await cmd.ExecuteReaderAsync();

                while (await dr.ReadAsync())
                {
                    //Asign every value with the info from the reader
                    client.Id = Convert.ToInt32(dr["Id"]);
                    client.FirstName = dr["FirstName"].ToString();
                    client.LastName = dr["LastName"].ToString();
                    client.Email = dr["Email"].ToString();

                    //Verify if Birthday field is not null
                    if (dr["Birthday"] != DBNull.Value)
                    {
                        client.Birthday = Convert.ToDateTime(dr["Birthday"]).Date;
                    }
                    else
                    {
                        client.Birthday = null;
                    }

                    //Temporal adjustment. Include address object and a JOIN in the stored procedure to bring the address object back
                    //Validate if AddressId is null
                    if (dr["AddressId"] != DBNull.Value)
                    {
                        client.AddressId = Convert.ToInt32(dr["AddressId"]);

                        //Create and asign address values
                        Address address = new Address();

                        address.Id = Convert.ToInt32(dr["AddressId"]);
                        address.Country = dr["Country"].ToString();
                        address.State = dr["State"].ToString();
                        address.City = dr["City"].ToString();
                        address.Street = dr["Street"].ToString();
                        address.ZipCode = Convert.ToInt32(dr["ZipCode"]);

                        client.Address = address;
                    }
                    else
                    {
                        client.AddressId = null;
                    }

                }

                return client;

            }
  
        }

        public async Task<Client> InsertClientAsync(Client client)
        {
            int success = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[csp_Insert_Client]";

                //Add every property as a parameter for the command

                //Client properties
                cmd.Parameters.AddWithValue("@FirstName", client.FirstName);
                cmd.Parameters.AddWithValue("@LastName", client.LastName);
                cmd.Parameters.AddWithValue("@Birthday", client.Birthday);
                cmd.Parameters.AddWithValue("@Email", client.Email);

                await conn.OpenAsync();

                success = await cmd.ExecuteNonQueryAsync();

                //Add the Id to the created client
                /*object result = await cmd.ExecuteScalarAsync();
                if (result != null)
                {
                    client.Id = (int)result;
                }*/

                return client;

            }

        }

        public async Task UpdateClientAsync(Client client)
        {
            int success = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[csp_Update_Client]";

                //Id parameter
                cmd.Parameters.AddWithValue("@Id", client.Id);

                //Add every property as a parameter for the command
                cmd.Parameters.AddWithValue("@FirstName", client.FirstName);
                cmd.Parameters.AddWithValue("@LastName", client.LastName);
                cmd.Parameters.AddWithValue("@Birthday", client.Birthday);
                cmd.Parameters.AddWithValue("@Email", client.Email);

                await conn.OpenAsync();

                success = await cmd.ExecuteNonQueryAsync();

            }
        }

        public async Task DeleteClientByIdAsync(int id)
        {
            int success = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[csp_Delete_Client]";
                cmd.Parameters.AddWithValue("@Id", id);

                await conn.OpenAsync();

                success = await cmd.ExecuteNonQueryAsync();
 
            }

        }

        public async Task<bool> ClientExistsbyIdAsync(int id)
        {
            int exists = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[csp_Client_ExistsbyId]";
                cmd.Parameters.AddWithValue("@Id", id);

                await conn.OpenAsync();

                exists = (int)await cmd.ExecuteScalarAsync();

                return Convert.ToBoolean(exists);

            }
        }
    }
}
