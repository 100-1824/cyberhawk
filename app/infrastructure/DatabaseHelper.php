<?php

/**
 * DatabaseHelper Class
 *
 * Purpose: Handles all database operations with prepared statements
 * Replaces: mysqli_prepared_query() function
 */
class DatabaseHelper {

    private $connection;

    /**
     * Constructor
     */
    public function __construct() {
        global $oConnection;
        $this->connection = $oConnection->dbc;
    }

    /**
     * Execute a prepared query with parameters
     *
     * @param string $sql The SQL query to execute
     * @param string $paramTypes Parameter types (e.g., 'ssi' for string, string, int)
     * @param array $params Array of parameters to bind
     * @return mixed Array of rows for SELECT, true for successful non-SELECT, false on failure
     */
    public function query($sql, $paramTypes = '', $params = []) {
        // Determine the query type
        $queryType = strtolower(trim(explode(" ", $sql)[0]));

        // Prepare the statement
        $stmt = $this->connection->prepare($sql);

        if ($stmt === false) {
            error_log("Database prepare failed: " . $this->connection->error);
            return false;
        }

        // Bind parameters if provided
        if (!empty($paramTypes) && !empty($params)) {
            $refp = array_merge([$paramTypes], $params);
            $pref = [];

            foreach ($refp as $key => $value) {
                $pref[$key] = &$refp[$key];
            }

            call_user_func_array([$stmt, 'bind_param'], $pref);
        }

        // Execute the statement
        $result = $stmt->execute();

        if ($result === true) {
            if ($queryType == "select") {
                // Fetch all rows for SELECT queries
                $resultSet = $stmt->get_result();
                $rows = $resultSet->fetch_all(MYSQLI_ASSOC);
                $stmt->close();
                return $rows;
            } else {
                // Return true for successful non-SELECT queries
                $stmt->close();
                return true;
            }
        } else {
            error_log("Database execute failed: " . $stmt->error);
            $stmt->close();
            return false;
        }
    }

    /**
     * Get the last insert ID
     *
     * @return int The last inserted ID
     */
    public function getLastInsertId() {
        return $this->connection->insert_id;
    }

    /**
     * Get affected rows count
     *
     * @return int Number of affected rows
     */
    public function getAffectedRows() {
        return $this->connection->affected_rows;
    }

    /**
     * Begin transaction
     */
    public function beginTransaction() {
        return $this->connection->begin_transaction();
    }

    /**
     * Commit transaction
     */
    public function commit() {
        return $this->connection->commit();
    }

    /**
     * Rollback transaction
     */
    public function rollback() {
        return $this->connection->rollback();
    }

    /**
     * Escape string for safe SQL usage
     *
     * @param string $string The string to escape
     * @return string The escaped string
     */
    public function escape($string) {
        return $this->connection->real_escape_string($string);
    }
}

?>
