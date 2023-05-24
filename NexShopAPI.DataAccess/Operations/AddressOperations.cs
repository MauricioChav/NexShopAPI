using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using NexShopAPI.DataAccess.IOperations;
using NexShopAPI.DataAccess.Models;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.DataAccess.Operations
{
    public class AddressOperations : IAddressOperation
    {
        //Connection and command
        SqlConnection conn = null;
        SqlCommand cmd = null;

        private readonly IConfiguration _config;
        private readonly string _connectionString;

        public AddressOperations(IConfiguration config)
        {
            _config = config;
            _connectionString = "DefaultConnection";
        }

        public async Task<Address> GetClientAddressAsync(int client_id)
        {
            Address address = new Address();
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[asp_Get_Client_Address]";
                cmd.Parameters.AddWithValue("@ClientId", client_id);

                await conn.OpenAsync();

                SqlDataReader dr = await cmd.ExecuteReaderAsync();

                while (await dr.ReadAsync())
                {
                    //Asign every value with the info from the reader
                    address.Id = Convert.ToInt32(dr["Id"]);
                    //address.ClientId = Convert.ToInt32(dr["ClientId"]);
                    address.Country = dr["Country"].ToString();
                    address.State = dr["State"].ToString();
                    address.City = dr["City"].ToString();
                    address.Street = dr["Street"].ToString();
                    address.ZipCode = Convert.ToInt32(dr["ZipCode"]);
                }

                return address;
            }
        }

        public async Task<Address> InsertClientAddressAsync(int client_id, Address address)
        {
            int success = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[asp_Insert_Address]";

                //Add every property as a parameter for the command

                //Add client_id
                cmd.Parameters.AddWithValue("@ClientId", client_id);

                //Address properties
                cmd.Parameters.AddWithValue("@Country", address.Country);
                cmd.Parameters.AddWithValue("@State", address.State);
                cmd.Parameters.AddWithValue("@City", address.City);
                cmd.Parameters.AddWithValue("@Street", address.Street);
                cmd.Parameters.AddWithValue("@ZipCode", address.ZipCode);

                await conn.OpenAsync();

                success = await cmd.ExecuteNonQueryAsync();
                return address;

            }
        }

        public async Task UpdateAddressAsync(int client_id, Address address)
        {
            int success = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[asp_Update_Address]";

                //Add every property as a parameter for the command

                //Add client_id
                cmd.Parameters.AddWithValue("@ClientId", client_id);

                //Address properties
                cmd.Parameters.AddWithValue("@Country", address.Country);
                cmd.Parameters.AddWithValue("@State", address.State);
                cmd.Parameters.AddWithValue("@City", address.City);
                cmd.Parameters.AddWithValue("@Street", address.Street);

                if(address.ZipCode != 0)
                cmd.Parameters.AddWithValue("@ZipCode", address.ZipCode);

                await conn.OpenAsync();

                success = await cmd.ExecuteNonQueryAsync();

            }
        }

        public async Task DeleteClientAddressAsync(int client_id)
        {
            int success = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[asp_Delete_Address]";
                cmd.Parameters.AddWithValue("@ClientId", client_id);

                await conn.OpenAsync();

                success = await cmd.ExecuteNonQueryAsync();

            }
        }

        public async Task<bool> AddressExistsbyClientIdAsync(int client_id)
        {
            int exists = 0;
            using (conn = new SqlConnection(_config.GetConnectionString(_connectionString)))
            {
                cmd = conn.CreateCommand();
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.CommandText = "[DBO].[asp_Address_ExistsbyClientId]";
                cmd.Parameters.AddWithValue("@ClientId", client_id);

                await conn.OpenAsync();

                exists = (int)await cmd.ExecuteScalarAsync();

                return Convert.ToBoolean(exists);
            }
        }
    }
}
