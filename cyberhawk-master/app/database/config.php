<?php

class dbConnection{

    private $host ="localhost"; 
    private $user = "root";
    private $password = ""; 
    private $db="cyberhawk";



    public $dbc;
    
    function __construct() {

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



 $globalWebsiteUrl = "http://localhost/contract/";



define('MDIR', '/cyberhawk/');
define("DIR", "E:/xampp/htdocs/cyberhawk/");  


?>