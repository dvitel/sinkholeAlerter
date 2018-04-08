module SinkholeAlerter.Db

open MySql.Data.MySqlClient

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
