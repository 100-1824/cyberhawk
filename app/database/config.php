<?php

class dbConnection{

    private $host;
    private $user;
    private $password;
    private $db;

    public $dbc;
    
    function __construct() {
        // Use environment variables with fallbacks for local development
        $this->host = getenv('DB_HOST') ?: 'localhost';
        $this->user = getenv('DB_USER') ?: 'root';
        $this->password = getenv('DB_PASSWORD') ?: '';
        $this->db = getenv('DB_NAME') ?: 'cyberhawk';

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



 $globalWebsiteUrl = getenv('APP_URL') ?: "http://localhost/contract/";



define('MDIR', '/cyberhawk/');
define("DIR", getenv('APP_DIR') ?: (PHP_OS_FAMILY === 'Windows' ? "E:/xampp/htdocs/cyberhawk/" : "/var/www/html/"));  

?>