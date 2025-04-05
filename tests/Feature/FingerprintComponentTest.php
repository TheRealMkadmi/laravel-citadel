<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\View;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Components\Fingerprint;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\Tests\TestCase;

class FingerprintComponentTest extends TestCase
{
    /**
     * Initialize the testing environment for fingerprint components
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Ensure the view exists and is registered
        View::addNamespace('citadel', __DIR__ . '/../../resources/views');
        
        // Set configuration for fingerprint component
        Config::set('citadel.cookie.expiration', 43200); // 30 days in minutes
        Config::set('citadel.cookie.name', 'citadel_visitor_id');
        Config::set('citadel.header.name', 'X-Fingerprint');
    }
    
    #[Test]
    public function fingerprint_component_renders_with_default_settings()
    {
        $component = new Fingerprint();
        $view = $component->render();
        
        $html = $view->render();
        
        // Verify essential elements are present in the rendered HTML
        $this->assertStringContainsString('script', $html);
        $this->assertStringContainsString('citadel_visitor_id', $html);
        $this->assertStringContainsString('X-Fingerprint', $html);
        
        // Check for automatic initialization
        $this->assertStringContainsString('FingerprintJS.load()', $html);
    }
    
    #[Test]
    public function fingerprint_component_respects_custom_settings()
    {
        // Create component with custom settings
        $component = new Fingerprint(
            false,  // disable auto-init
            60,     // 1 hour expiration
            'custom_cookie_name',
            'Custom-Header-Name'
        );
        
        $view = $component->render();
        $html = $view->render();
        
        // Check for custom values in the rendered output
        $this->assertStringContainsString('custom_cookie_name', $html);
        $this->assertStringContainsString('Custom-Header-Name', $html);
        
        // Should not have auto-initialization
        $this->assertStringNotContainsString('window.onload', $html);
    }
    
    #[Test]
    public function fingerprint_component_produces_valid_javascript()
    {
        $component = new Fingerprint();
        $view = $component->render();
        $html = $view->render();
        
        // Check for valid JavaScript syntax elements
        $this->assertStringContainsString('function', $html);
        $this->assertStringContainsString('document.cookie', $html);
        $this->assertStringContainsString('XMLHttpRequest', $html);
        
        // Check for security practices in cookie setting
        $this->assertStringContainsString('path=/', $html);
        $this->assertStringContainsString('SameSite', $html);
    }
    
    #[Test]
    public function fingerprint_component_sets_appropriate_cookie_expiration()
    {
        // Configure a specific expiration time
        $testExpirationMinutes = 60 * 24; // 1 day in minutes
        
        $component = new Fingerprint(true, $testExpirationMinutes);
        $view = $component->render();
        $html = $view->render();
        
        // The cookie expiration should be expressed in the JavaScript
        $this->assertStringContainsString('max-age=' . ($testExpirationMinutes * 60), $html);
    }
}