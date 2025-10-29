import { Injectable, Logger } from '@nestjs/common';
import * as uuid from 'uuid';
import { oneLine } from 'common-tags';
import { config } from '../config';
import { StandardError } from '../common';

export interface MinecraftOfficialProfile {
  uuid: string;
  username: string | null;
}

export abstract class MinecraftAuthError extends StandardError {}

export class MinecraftAuthRequestError extends MinecraftAuthError {
  public readonly status?: number;

  public constructor(message: string, status?: number) {
    super(message);

    this.status = status;
  }
}

export class MinecraftAuthInvalidAccessTokenError extends MinecraftAuthError {
  public constructor() {
    super(`Invalid or expired Minecraft access token.`);
  }
}

export class MinecraftAuthMalformedResponseError extends MinecraftAuthError {
  public constructor() {
    super(`Received an unexpected response from the Minecraft profile service.`);
  }
}

export class MinecraftAuthInvalidUuidError extends MinecraftAuthError {
  public readonly value: string;

  public constructor(value: string) {
    super(`Invalid Minecraft UUID "${value}".`);

    this.value = value;
  }
}

@Injectable()
export class MinecraftAuthService {
  private readonly logger = new Logger(MinecraftAuthService.name);

  public normalizeUuid(input: string): string {
    const compact = input.replaceAll('-', '').toLowerCase();

    if (compact.length != 32) {
      throw new MinecraftAuthInvalidUuidError(input);
    }

    const hyphenated = `${compact.slice(0, 8)}-${compact.slice(8, 12)}-${compact.slice(12, 16)}-${compact.slice(16, 20)}-${compact.slice(20)}`;

    if (!uuid.validate(hyphenated)) {
      throw new MinecraftAuthInvalidUuidError(input);
    }

    return hyphenated;
  }

  public async verifyOfficialAccount({
    accessToken
  }: {
    accessToken: string;
  }): Promise<MinecraftOfficialProfile> {
    let response: Response;

    try {
      response = await fetch(config.minecraftAuth.profileUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json'
        }
      });
    } catch (error) {
      this.logger.error(`Failed to call Minecraft profile service.`, error);
      throw new MinecraftAuthRequestError(
        `Unable to contact the Minecraft profile service, please try again later.`
      );
    }

    if (response.status == 401 || response.status == 403) {
      throw new MinecraftAuthInvalidAccessTokenError();
    }

    if (!response.ok) {
      throw new MinecraftAuthRequestError(
        oneLine`Unexpected response from the Minecraft profile service (status ${response.status}).`,
        response.status
      );
    }

    let payload: unknown;

    try {
      payload = await response.json();
    } catch (error) {
      this.logger.error(`Failed to parse Minecraft profile response.`, error);
      throw new MinecraftAuthMalformedResponseError();
    }

    if (!payload || typeof payload != 'object') {
      throw new MinecraftAuthMalformedResponseError();
    }

    const id = 'id' in payload ? payload.id : undefined;
    const name = 'name' in payload ? payload.name : undefined;

    if (typeof id != 'string' || !id.length) {
      throw new MinecraftAuthMalformedResponseError();
    }

    const uuidValue = this.normalizeUuid(id);
    const username = typeof name == 'string' && name.trim().length ? name.trim() : null;

    return { uuid: uuidValue, username };
  }
}
