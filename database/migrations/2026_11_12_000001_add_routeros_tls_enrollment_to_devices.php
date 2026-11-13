<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('devices', function (Blueprint $table): void {
            $table->timestamp('routeros_tls_enrolled_at')->nullable();
            $table->timestamp('routeros_tls_attempted_at')->nullable();
            $table->string('routeros_tls_status', 16)->nullable();
            $table->string('routeros_tls_error', 255)->nullable();
            $table->timestamp('routeros_tls_expires_at')->nullable();
            $table->string('routeros_tls_fingerprint', 64)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('devices', function (Blueprint $table): void {
            $table->dropColumn([
                'routeros_tls_enrolled_at',
                'routeros_tls_attempted_at',
                'routeros_tls_status',
                'routeros_tls_error',
                'routeros_tls_expires_at',
                'routeros_tls_fingerprint',
            ]);
        });
    }
};
