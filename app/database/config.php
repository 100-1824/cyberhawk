<?php

class dbConnection{

    private $host;
    private $user;
    private $password;
    private $db;

    public $dbc;

    function __construct() {
        // Load database credentials from environment variables
        $this->host = env('DB_HOST', 'localhost');
        $this->user = env('DB_USERNAME', 'root');
        $this->password = env('DB_PASSWORD', '');
        $this->db = env('DB_DATABASE', 'cyberhawk');

        $mysqli = new MySQLi($this->host, $this->user, $this->password, $this->db);

        if(mysqli_errno($mysqli)){
            die();
            echo"Connection Error";

        }
        else{
           $this->dbc = $mysqli;

        }
    }
}



 $globalWebsiteUrl = env('APP_URL', 'http://localhost/cyberhawk/');

// Note: MDIR and DIR constants are now defined in app/bootstrap.php

?>