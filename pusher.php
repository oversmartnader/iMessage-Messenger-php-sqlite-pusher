<?php

class PusherClient {
    private $appId;
    private $key;
    private $secret;
    private $cluster;
    private $host;
    private $timeout;
    
    public function __construct($appId, $key, $secret, $cluster = 'us2', $timeout = 10) {
        if (empty($appId) || empty($key) || empty($secret)) {
            throw new InvalidArgumentException('Pusher credentials are required');
        }
        
        $this->appId = $appId;
        $this->key = $key;
        $this->secret = $secret;
        $this->cluster = $cluster;
        $this->host = "api-{$cluster}.pusher.com";
        $this->timeout = $timeout;
    }
    
    public function trigger($channels, $event, $data, $socketId = null) {
        if (empty($channels) || empty($event)) {
            return false;
        }
        
        if (!is_array($channels)) {
            $channels = [$channels];
        }
        
        $channels = array_slice($channels, 0, 100);
        
        $payload = [
            'name' => $event,
            'channels' => array_values($channels),
            'data' => is_string($data) ? $data : json_encode($data)
        ];
        
        if ($socketId && $this->validateSocketId($socketId)) {
            $payload['socket_id'] = $socketId;
        }
        
        $path = "/apps/{$this->appId}/events";
        $body = json_encode($payload);
        
        return $this->apiRequest('POST', $path, $body);
    }
    
    public function triggerBatch($batch) {
        if (empty($batch) || !is_array($batch)) {
            return false;
        }
        
        $batch = array_slice($batch, 0, 10);
        
        $events = [];
        foreach ($batch as $item) {
            if (empty($item['channel']) || empty($item['name'])) {
                continue;
            }
            
            $event = [
                'channel' => $item['channel'],
                'name' => $item['name'],
                'data' => is_string($item['data'] ?? '') ? ($item['data'] ?? '') : json_encode($item['data'] ?? [])
            ];
            
            if (!empty($item['socket_id']) && $this->validateSocketId($item['socket_id'])) {
                $event['socket_id'] = $item['socket_id'];
            }
            
            $events[] = $event;
        }
        
        if (empty($events)) {
            return false;
        }
        
        $path = "/apps/{$this->appId}/batch_events";
        $body = json_encode(['batch' => $events]);
        
        return $this->apiRequest('POST', $path, $body);
    }
    
    public function socketAuth($channelName, $socketId, $userData = null) {
        if (!$this->validateSocketId($socketId)) {
            throw new InvalidArgumentException('Invalid socket ID format');
        }
        
        if (!$this->validateChannelName($channelName)) {
            throw new InvalidArgumentException('Invalid channel name');
        }
        
        $isPresenceChannel = strpos($channelName, 'presence-') === 0;
        $isPrivateChannel = strpos($channelName, 'private-') === 0;
        
        if (!$isPresenceChannel && !$isPrivateChannel) {
            throw new InvalidArgumentException('Channel must be private or presence');
        }
        
        if ($isPresenceChannel) {
            if (empty($userData) || !isset($userData['user_id'])) {
                throw new InvalidArgumentException('Presence channels require user_id in userData');
            }
            
            $userDataJson = json_encode($userData);
            $stringToSign = $socketId . ':' . $channelName . ':' . $userDataJson;
            $signature = hash_hmac('sha256', $stringToSign, $this->secret);
            
            return json_encode([
                'auth' => $this->key . ':' . $signature,
                'channel_data' => $userDataJson
            ]);
        }
        
        $stringToSign = $socketId . ':' . $channelName;
        $signature = hash_hmac('sha256', $stringToSign, $this->secret);
        
        return json_encode([
            'auth' => $this->key . ':' . $signature
        ]);
    }
    
    public function getChannelInfo($channelName, $info = []) {
        if (!$this->validateChannelName($channelName)) {
            return false;
        }
        
        $path = "/apps/{$this->appId}/channels/" . urlencode($channelName);
        $queryParams = [];
        
        if (!empty($info)) {
            $queryParams['info'] = implode(',', $info);
        }
        
        return $this->apiRequest('GET', $path, null, $queryParams);
    }
    
    public function getChannels($prefix = null, $info = []) {
        $path = "/apps/{$this->appId}/channels";
        $queryParams = [];
        
        if ($prefix) {
            $queryParams['filter_by_prefix'] = $prefix;
        }
        
        if (!empty($info)) {
            $queryParams['info'] = implode(',', $info);
        }
        
        return $this->apiRequest('GET', $path, null, $queryParams);
    }
    
    public function getPresenceUsers($channelName) {
        if (strpos($channelName, 'presence-') !== 0) {
            return false;
        }
        
        $path = "/apps/{$this->appId}/channels/" . urlencode($channelName) . "/users";
        
        return $this->apiRequest('GET', $path);
    }
    
    private function apiRequest($method, $path, $body = null, $extraParams = []) {
        $timestamp = time();
        $bodyMd5 = $body ? md5($body) : md5('');
        
        $queryParams = array_merge([
            'auth_key' => $this->key,
            'auth_timestamp' => $timestamp,
            'auth_version' => '1.0',
            'body_md5' => $bodyMd5
        ], $extraParams);
        
        ksort($queryParams);
        $queryString = http_build_query($queryParams);
        
        $stringToSign = "{$method}\n{$path}\n{$queryString}";
        $authSignature = hash_hmac('sha256', $stringToSign, $this->secret);
        
        $url = "https://{$this->host}{$path}?{$queryString}&auth_signature={$authSignature}";
        
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'PusherPHP/1.0'
        ]);
        
        if ($body && in_array($method, ['POST', 'PUT', 'PATCH'])) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($body)
            ]);
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        $curlErrno = curl_errno($ch);
        
        curl_close($ch);
        
        if ($curlErrno) {
            error_log("Pusher curl error ({$curlErrno}): {$curlError}");
            return false;
        }
        
        if ($httpCode >= 200 && $httpCode < 300) {
            if (empty($response)) {
                return true;
            }
            $decoded = json_decode($response, true);
            return $decoded !== null ? $decoded : true;
        }
        
        error_log("Pusher API error: HTTP {$httpCode} - {$response}");
        return false;
    }
    
    private function validateSocketId($socketId) {
        if (empty($socketId) || !is_string($socketId)) {
            return false;
        }
        return (bool) preg_match('/^\d+\.\d+$/', $socketId);
    }
    
    private function validateChannelName($channelName) {
        if (empty($channelName) || !is_string($channelName)) {
            return false;
        }
        if (strlen($channelName) > 200) {
            return false;
        }
        return (bool) preg_match('/^[a-zA-Z0-9_\-=@,.;]+$/', $channelName);
    }
    
    public function getKey() {
        return $this->key;
    }
    
    public function getCluster() {
        return $this->cluster;
    }
}