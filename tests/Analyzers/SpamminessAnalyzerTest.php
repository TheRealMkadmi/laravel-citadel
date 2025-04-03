<?php

namespace TheRealMkadmi\Citadel\Tests\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\SpamminessAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;
use Symfony\Component\HttpFoundation\InputBag;

class SpamminessAnalyzerTest extends TestCase
{
    protected SpamminessAnalyzer $analyzer;
    protected ArrayDataStore $dataStore;
    
    protected function setUp(): void
    {
        parent::setUp();
        $this->dataStore = new ArrayDataStore();
        $this->analyzer = new SpamminessAnalyzer($this->dataStore);
    }
    
    #[Test]
    public function it_detects_gibberish_text()
    {
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-1',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => 'asdfghjklqwertyuiopzxcvbnm']);

        $score = $this->analyzer->analyze($request);
        
        $this->assertGreaterThan(0, $score, 'Expected SpamminessAnalyzer to detect keyboard pattern gibberish.');
    }
    
    #[Test]
    public function it_scores_repetitive_content()
    {
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-2',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => 'spam spam spam spam spam spam spam']);

        $score = $this->analyzer->analyze($request);
        
        $this->assertGreaterThan(0, $score, 'Expected SpamminessAnalyzer to score repetitive content.');
    }
    
    #[Test]
    public function it_caches_analysis_results()
    {
        // Define a consistent fingerprint for cache testing
        $fingerprint = 'consistent-fingerprint';
        
        $request = $this->makeFingerprintedRequest(
            $fingerprint,
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => 'normal text for caching']);

        $score1 = $this->analyzer->analyze($request);
        
        // Create a new request with the same fingerprint
        $newRequest = $this->makeFingerprintedRequest(
            $fingerprint,
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $newRequest->json()->replace(['message' => 'normal text for caching']);
        
        $score2 = $this->analyzer->analyze($newRequest);

        $this->assertEquals($score1, $score2, 'Expected SpamminessAnalyzer to cache analysis results based on fingerprint.');
    }
    
    #[Test]
    public function it_respects_disabled_setting()
    {
        // Temporarily disable the analyzer
        Config::set('citadel.spamminess.enable_spamminess_analyzer', false);
        
        // Reinstantiate the analyzer to pick up the config change
        $this->analyzer = new SpamminessAnalyzer($this->dataStore);
        
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-3',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => 'qwertyuiop']); // This would normally trigger detection

        $score = $this->analyzer->analyze($request);
        
        $this->assertEquals(0.0, $score, 'Expected SpamminessAnalyzer to respect disabled setting.');
    }
    
    #[Test]
    #[DataProvider('keyboardPatternProvider')]
    public function it_detects_keyboard_patterns(string $text, bool $shouldDetect)
    {
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-patterns',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => $text]);

        $score = $this->analyzer->analyze($request);
        
        if ($shouldDetect) {
            $this->assertGreaterThan(0, $score, "Expected to detect keyboard pattern in: $text");
        } else {
            $this->assertEquals(0.0, $score, "Should not detect keyboard pattern in: $text");
        }
    }
    
    public static function keyboardPatternProvider(): array
    {
        return [
            'qwerty pattern' => ['qwertyuiop1234', true],
            'asdf pattern' => ['asdfghjkl', true],
            'sequential numbers' => ['12345678', true],
            'normal text' => ['Hello, this is a normal text message', false],
            'short text' => ['hi', false],
        ];
    }
    
    #[Test]
    #[DataProvider('spamPatternProvider')]
    public function it_detects_spam_patterns(string $text, bool $shouldDetect)
    {
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-spam',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => $text]);

        $score = $this->analyzer->analyze($request);
        
        if ($shouldDetect) {
            $this->assertGreaterThan(0, $score, "Expected to detect spam pattern in: $text");
        } else {
            $this->assertEquals(0.0, $score, "Should not detect spam pattern in: $text");
        }
    }
    
    public static function spamPatternProvider(): array
    {
        return [
            'keyboard mashing' => ['sdkfjhsdkfjh', true],
            'random characters' => ['djf93jfnvuw89e4', true],
            'mixed gibberish' => ['a$d^f*g#h@j!k?l', true],
            'random repetition' => ['blah blah blah blah blah', true],
            'special characters spam' => ['!@#$%^&*()_+!@#$%^&*()', true],
            'no spaces gibberish' => ['thisisnotarealsentencejustgarbage', true], 
            'alternating case gibberish' => ['AbCdEfGhIjKlMnOpQrS', true],
            'normal text' => ['I would like to inquire about your services', false],
        ];
    }
    
    #[Test]
    #[DataProvider('entropyTextProvider')] 
    public function it_analyzes_text_entropy(string $text, bool $shouldFlag)
    {
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-entropy',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => $text]);

        $score = $this->analyzer->analyze($request);
        
        if ($shouldFlag) {
            $this->assertGreaterThan(0, $score, "Text should be flagged for unusual entropy: $text");
        } else {
            $this->assertEquals(0.0, $score, "Text should not be flagged for entropy: $text");
        }
    }
    
    public static function entropyTextProvider(): array
    {
        return [
            'very low entropy' => ['aaaaaaaaaaaaaaaaaaaa', true],
            'very high entropy' => ['j8%4@xL!p9&Z*q2#mR5', true],
            'normal english' => ['This is a normal English sentence with typical entropy.', false],
        ];
    }
    
    #[Test]
    #[DataProvider('repetitiveContentProvider')]
    public function it_detects_repetitive_content(string $text, bool $shouldDetect)
    {
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-repetitive',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => $text]);

        $score = $this->analyzer->analyze($request);
        
        if ($shouldDetect) {
            $this->assertGreaterThan(0, $score, "Should detect repetitive content: $text");
        } else {
            $this->assertEquals(0.0, $score, "Should not detect repetitive content: $text");
        }
    }
    
    public static function repetitiveContentProvider(): array
    {
        return [
            'repeated characters' => ['aaaaabbbbbbccccccddddd', true],
            'repeated words' => ['spam spam spam spam spam spam spam', true],
            'normal text' => ['This sentence has a normal distribution of different words', false],
        ];
    }
    
    #[Test]
    public function it_handles_nested_data_structures()
    {
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-nested',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        
        // Create a complex nested structure with one spam element
        $data = [
            'user' => [
                'name' => 'John Doe',
                'email' => 'john@example.com',
            ],
            'comments' => [
                ['text' => 'This is fine'],
                ['text' => 'This is also good'],
                ['text' => 'qwertyuiopasdfghjkl'],  // This should trigger detection
            ],
            'metadata' => [
                'timestamp' => time(),
                'source' => 'web',
            ],
        ];
        
        $request->json()->replace($data);

        $score = $this->analyzer->analyze($request);
        
        $this->assertGreaterThan(0, $score, 'Expected SpamminessAnalyzer to detect spam in nested structures');
    }
    
    #[Test]
    public function it_handles_empty_and_short_input()
    {
        // Test empty input
        $emptyRequest = $this->makeFingerprintedRequest(
            'test-fingerprint-empty',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $emptyRequest->json()->replace(['message' => '']);
        
        $emptyScore = $this->analyzer->analyze($emptyRequest);
        $this->assertEquals(0.0, $emptyScore, 'Empty input should score 0');
        
        // Test very short input (below min_field_length)
        $shortRequest = $this->makeFingerprintedRequest(
            'test-fingerprint-short',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $shortRequest->json()->replace(['message' => 'a']);
        
        $shortScore = $this->analyzer->analyze($shortRequest);
        $this->assertEquals(0.0, $shortScore, 'Very short input should score 0');
    }
    
    #[Test]
    public function it_handles_very_long_input()
    {
        // Generate a very long text (over 10,000 chars)
        $longText = str_repeat('This is a normal sentence. ', 500);
        
        // Insert some spam in the middle
        $spamInsertPosition = strlen($longText) / 2;
        $longTextWithSpam = substr($longText, 0, $spamInsertPosition) . 
                            'qwertyuiop FREE OFFER!!! ' . 
                            substr($longText, $spamInsertPosition);
        
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint-long',
            'POST',
            'https://example.com/test',
            [],
            ['HTTP_USER_AGENT' => 'TestAgent']
        );
        $request->json()->replace(['message' => $longTextWithSpam]);
        
        $score = $this->analyzer->analyze($request);
        
        $this->assertGreaterThan(0, $score, 'Should detect spam in very long text');
    }
}