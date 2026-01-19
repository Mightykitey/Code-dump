<?php
// date base connection
    function dabco_insert(){
        //they should not be stored in plain text in open code here. can be stored in a file or set them as  environment verlable in web server software
        $servername = "localhost"; //had to change this variable name as it fought against the adim reg

        $dbusername = "root"; //shound not use root in a productive. anyone will have total right to the datebase

        $dbpassword = '';

        $dbname = "gconsole";

        try{
            $conn= new PDO("mysql:host=$servername;port=3306;dbname=$dbname", $dbusername, $dbpassword); //alternative for PDO could be mysqli is being pushed out. PDO will connect to any kind of data source form one compound set only need to change the location of the data base.
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // error mode
            return $conn;
        }catch(PDOException $e){//catch statement if it fails
            error_log("databaseerror in super_checker: ".$e->getMessage());

            throw $e; // Re-throw the exception (output the error)
        }



    }