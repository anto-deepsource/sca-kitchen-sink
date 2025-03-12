<?php

require 'vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use PHPMailer\PHPMailer\PHPMailer;
use GuzzleHttp\Client;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Doctrine\ORM\EntityManager;

class VulnerableDemo
{
    public function demonstrateVulnerabilities()
    {
        // Symfony HttpFoundation Cache Poisoning (CVE-2019-18888)
        $request = Request::createFromGlobals();
        $response = new Response('Content');
        $response->setVary(['Accept-Encoding']);
        $response->setCache([
            'max_age' => 3600,
            'public' => true,
        ]);

        // PHPMailer RCE Vulnerability (CVE-2020-36326)
        $mail = new PHPMailer(true);
        try {
            $mail->setFrom('attacker@example.com>', 'Attacker');
            $mail->addAddress('victim@example.com');
            $mail->Subject = 'Test Subject';
            $mail->Body = 'Test Body';
            $mail->send();
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }

        // Guzzle SSRF Vulnerability (CVE-2020-25613)
        $client = new Client();
        $userInput = 'http://internal-service/api';
        try {
            $response = $client->request('GET', $userInput, [
                'allow_redirects' => true // Vulnerable to SSRF
            ]);
        } catch (Exception $e) {
            echo $e->getMessage();
        }

        // Monolog Information Disclosure (CVE-2021-43797)
        $log = new Logger('vulnerable_logger');
        $log->pushHandler(new StreamHandler('logs/app.log', Logger::DEBUG));
        $log->info('Sensitive information', [
            'password' => 'secret123',
            'api_key' => 'ak_live_123456789'
        ]);

        // Doctrine ORM SQL Injection (CVE-2020-15148)
        $userInput = "admin' OR '1'='1";
        $dql = "SELECT u FROM User u WHERE u.username = '" . $userInput . "'";
        // Vulnerable when using raw DQL queries
    }
}

$demo = new VulnerableDemo();
$demo->demonstrateVulnerabilities(); 