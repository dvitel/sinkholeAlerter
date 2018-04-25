module SinkholeAlerter.Db

open MySql.Data.MySqlClient

///<summary>
///async quering db fro data through ADO.NET and MySQLConnector
///</summary>
///<param name='connectionString'>
///Connection string to MySQL db, see config.json for example
///</param>
///<param name='query'>
///MySQL query
///</param>
///<param name='parameters'>
///parameters to be passed to query in secured way (through @0, @1, etc)
///</param>
///<param name='readEntity'>
///callback function on each read of entity - should parse and build entity and put it in acc
///</param>
///<param name='initialAcc'>
///empty collection (usually linked list [], or map Map<_,_>) to collect data into
///</param>
let queryDbAsync connectionString query (parameters: Map<string, obj>) readEntity initialAcc = async {
    use conn = new MySqlConnection(connectionString)
    do! Async.AwaitTask(conn.OpenAsync())
    use cmd = conn.CreateCommand()
    cmd.CommandText <- query 
    let parameters = 
        parameters |> Map.fold(fun acc name value -> 
            MySqlParameter(name, value)::acc
        ) [] |> List.toArray
    cmd.Parameters.AddRange(parameters)
    use! reader = Async.AwaitTask(cmd.ExecuteReaderAsync())
    let rec readReader acc = async {
        let! hasNextRecord = Async.AwaitTask(reader.ReadAsync())
        if hasNextRecord then 
            return! readReader (readEntity reader acc)
        else 
            return acc
    }
    return! readReader initialAcc
}
