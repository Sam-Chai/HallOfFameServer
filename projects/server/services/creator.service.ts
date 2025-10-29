import assert from 'node:assert/strict';
import { ForbiddenException, Inject, Injectable, Logger } from '@nestjs/common';
import type { Creator } from '@prisma/client';
import * as sentry from '@sentry/bun';
import { oneLine } from 'common-tags';
import * as uuid from 'uuid';
import {
  type CreatorId,
  type HardwareId,
  type IpAddress,
  isPrismaError,
  type JsonObject,
  StandardError
} from '../common';
import { config } from '../config';
import { AiTranslatorService } from './ai-translator.service';
import { PrismaService } from './prisma.service';
import {
  MinecraftAuthError,
  MinecraftAuthInvalidUuidError,
  MinecraftAuthService
} from './minecraft-auth.service';

export type CreatorAuthorization = SimpleCreatorAuthorization | ModCreatorAuthorization;

/**
 * The simpler authorization scheme.
 * Allows logging in to an existing account with just a Creator ID, much like an API key.
 *
 * @see CreatorService.authenticateCreatorSimple
 */
export type SimpleCreatorAuthorization = Readonly<{
  kind: 'simple';
  creatorId: CreatorId;
  ip: IpAddress;
}>;

/**
 * More complex authorization scheme used by the mod.
 * It serves many purposes: checking that the Creator ID is correct, but also creating an account
 * from scratch (to allow register-less setup of Hall of Fame), or update account info like the
 * Creator name.
 *
 * @see CreatorService.authenticateCreatorForMod
 */
export type ModCreatorAuthorization = Readonly<{
  kind: 'mod';
  creatorName: Creator['creatorName'];
  creatorId: CreatorId;
  creatorIdProvider: Creator['creatorIdProvider'];
  hwid: HardwareId;
  ip: IpAddress;
  minecraftAccessToken?: string;
  minecraftPlayerUuid?: string;
}>;

/**
 * Service to manage and authenticate Creators.
 */
@Injectable()
export class CreatorService {
  @Inject(PrismaService)
  private readonly prisma!: PrismaService;

  @Inject(AiTranslatorService)
  private readonly aiTranslator!: AiTranslatorService;

  @Inject(MinecraftAuthService)
  private readonly minecraftAuth!: MinecraftAuthService;

  private readonly logger = new Logger(CreatorService.name);

  /**
   * Authenticates a creator based on the provided authorization kind and details.
   *
   * @see authenticateCreatorSimple
   * @see authenticateCreatorForMod
   */
  public async authenticateCreator(authorization: CreatorAuthorization): Promise<Creator> {
    switch (authorization.kind) {
      case 'simple':
        this.ensureValidCreatorId(authorization.creatorId);
        return await this.authenticateCreatorSimple(authorization);
      case 'mod':
        return await this.authenticateCreatorForMod(authorization);
      default:
        throw authorization satisfies never;
    }
  }

  /**
   * Contrarily to {@link authenticateCreatorForMod} which performs complex logic (creator ID/name
   * matching + account creation + account update), this method is more like a `checkApiKey()` and
   * only checks that the given Creator ID matches a creator, at which point you are considered
   * authenticated.
   */
  private async authenticateCreatorSimple({
    creatorId,
    ip
  }: SimpleCreatorAuthorization): Promise<Creator> {
    let creator = await this.prisma.creator.findUnique({ where: { creatorId } });

    if (!creator) {
      throw new CreatorNotFoundError();
    }

    // Update the last used IP address if it changed.
    if (creator.ips[0] != ip) {
      creator = await this.prisma.creator.update({
        where: { id: creator.id },
        data: {
          ips: Array.from(new Set([ip, ...creator.ips])).slice(0, 3)
        }
      });
    }

    return creator;
  }

  /**
   * Creates a new Creator or retrieves an existing one.
   * This method is to be used as authentication and account creation as it performs Creator Name/
   * Creator ID validation and updates.
   *
   * There are two possible outcomes:
   * - If the Creator ID doesn't match any record, a new Creator is created with the provided
   *   credentials.
   * - If the Creator ID matches a record, the request is authenticated, and the Creator Name is
   *   updated if it is changed.
   *
   * This is only a wrapper around {@link authenticateCreatorForModUnsafe} that handles concurrent
   * requests conflicts.
   */
  private async authenticateCreatorForMod(
    authorization: ModCreatorAuthorization
  ): Promise<Creator> {
    try {
      return await this.authenticateCreatorForModUnsafe(authorization);
    } catch (error) {
      // This can happen if a Creator account didn't exist and that user simultaneously sends
      // two authenticated requests that lead to the creation of the same Creator account due
      // to race condition, for example, "/me" and "/me/stats" when launching the mod.
      // In that case we only have to retry the authentication.
      if (isPrismaError(error) && error.code == 'P2002') {
        return await this.authenticateCreatorForModUnsafe(authorization);
      }

      throw error;
    }
  }

  /**
   * See {@link authenticateCreatorForMod} for the method's purpose, this is only the part of the
   * authentication that can be retried in case of error due to concurrent requests leading to an
   * account creation (and therefore a unique constraint violation).
   */
  // biome-ignore lint/complexity/noExcessiveLinesPerFunction: it's long, but better that way.
  public async authenticateCreatorForModUnsafe({
    creatorId: rawCreatorId,
    creatorIdProvider,
    creatorName,
    hwid,
    ip,
    minecraftAccessToken,
    minecraftPlayerUuid
  }: ModCreatorAuthorization): Promise<Creator> {
    // Note: we do NOT validate the Creator Name immediately, as we need to support legacy
    // Creator Names that were validated with a different regex.
    // We validate it only when an account is created or updated.

    let effectiveCreatorId = rawCreatorId;
    let effectiveCreatorName = creatorName;
    let effectiveMinecraftPlayerUuid: string | null = null;

    switch (creatorIdProvider) {
      case 'minecraft_official': {
        if (!minecraftAccessToken?.trim()) {
          throw new MissingMinecraftOfficialAccessTokenError();
        }

        try {
          const profile = await this.minecraftAuth.verifyOfficialAccount({
            accessToken: minecraftAccessToken
          });
          effectiveCreatorId = profile.uuid;
          effectiveMinecraftPlayerUuid = profile.uuid;
          if (!effectiveCreatorName && profile.username) {
            effectiveCreatorName = profile.username;
          }
        } catch (error) {
          if (error instanceof MinecraftAuthError) {
            throw new MinecraftOfficialAuthenticationError(error);
          }

          throw error;
        }

        break;
      }

      case 'minecraft_offline': {
        if (!minecraftPlayerUuid?.trim()) {
          throw new MissingMinecraftOfflinePlayerUuidError();
        }

        try {
          effectiveMinecraftPlayerUuid = this.minecraftAuth.normalizeUuid(minecraftPlayerUuid);
        } catch (error) {
          if (error instanceof MinecraftAuthInvalidUuidError) {
            throw new InvalidMinecraftPlayerUuidError(minecraftPlayerUuid);
          }

          throw error;
        }
        break;
      }

      case 'paradox':
      case 'local':
        break;

      default:
        throw new UnsupportedCreatorIdProviderError(creatorIdProvider);
    }

    this.ensureValidCreatorId(effectiveCreatorId);

    const creatorNameSlug = this.getCreatorNameSlug(effectiveCreatorName);
    const searchConditions = [
      { creatorId: effectiveCreatorId }
    ];

    if (effectiveCreatorName) {
      searchConditions.push(
        { creatorName: effectiveCreatorName },
        { creatorNameSlug }
      );
    }

    if (effectiveMinecraftPlayerUuid) {
      searchConditions.push({ minecraftPlayerUuid: effectiveMinecraftPlayerUuid });
    }

    const creators = await this.prisma.creator.findMany({
      where:
        searchConditions.length > 1
          ? {
              // biome-ignore lint/style/useNamingConvention: prisma query
              OR: searchConditions
            }
          : searchConditions[0]
    });

    // This can happen if we matched an existing Creator ID (so far so good) but that the
    // Creator Name is being changed to a name that is already taken.
    // This returns two creators, one matching the Creator ID and one matching the Creator Name.
    if (creators.length > 1) {
      assert(
        creators.length == 2,
        `Only two creators are returned, otherwise there are non-unique Creator Names.`
      );

      assert(
        effectiveCreatorName,
        `Creator Name can only be non-null if >1 creators are found.`
      );

      throw new IncorrectCreatorIdError(effectiveCreatorName);
    }

    // After this previous check we know that the first and only creator is the one we want to
    // authenticate or create.
    const creator = creators[0];

    return creator
      ? updateCreator.call(this, {
          effectiveCreatorId,
          effectiveCreatorName,
          effectiveMinecraftPlayerUuid,
          creatorNameSlug,
          hwid,
          ip,
          creatorIdProvider
        })
      : createCreator.call(this, {
          effectiveCreatorId,
          effectiveCreatorName,
          effectiveMinecraftPlayerUuid,
          creatorNameSlug,
          hwid,
          ip,
          creatorIdProvider
        });

    interface CreatorContext {
      effectiveCreatorId: string;
      effectiveCreatorName: string | null;
      effectiveMinecraftPlayerUuid: string | null;
      creatorNameSlug: string | null;
      hwid: HardwareId;
      ip: IpAddress;
      creatorIdProvider: Creator['creatorIdProvider'];
    }

    async function createCreator(
      this: CreatorService,
      {
        effectiveCreatorId,
        effectiveCreatorName,
        effectiveMinecraftPlayerUuid,
        creatorNameSlug,
        hwid,
        ip,
        creatorIdProvider
      }: CreatorContext
    ): Promise<Creator> {
      // Create a new creator.
      const newCreator = await this.prisma.creator.create({
        data: {
          creatorId: effectiveCreatorId,
          creatorIdProvider,
          creatorName: CreatorService.validateCreatorName(effectiveCreatorName),
          creatorNameSlug,
          minecraftPlayerUuid: effectiveMinecraftPlayerUuid,
          hwids: [hwid],
          ips: [ip],
          socials: []
        }
      });

      backgroundUpdateCreatorNameTranslation.call(this, newCreator);

      this.logger.log(`Created creator "${newCreator.creatorName}".`);

      return newCreator;
    }

    async function updateCreator(
      this: CreatorService,
      {
        effectiveCreatorId,
        effectiveCreatorName,
        effectiveMinecraftPlayerUuid,
        creatorNameSlug,
        hwid,
        ip,
        creatorIdProvider
      }: CreatorContext
    ): Promise<Creator> {
      assert(creator);

      // Check if the Creator ID match, unless the reset flag is set.
      const isSameMinecraftPlayer =
        effectiveMinecraftPlayerUuid &&
        creator.minecraftPlayerUuid == effectiveMinecraftPlayerUuid;

      if (
        creator.creatorId != effectiveCreatorId &&
        !creator.allowCreatorIdReset &&
        !isSameMinecraftPlayer
      ) {
        // This should never happen, as when we enter this condition, it means that we matched
        // on the Creator Name and not the Creator ID.
        assert(creator.creatorName);

        throw new IncorrectCreatorIdError(creator.creatorName);
      }

      const modified =
        creator.creatorName != effectiveCreatorName ||
        creator.creatorNameSlug != creatorNameSlug ||
        creator.hwids[0] != hwid ||
        creator.ips[0] != ip ||
        creator.creatorId != effectiveCreatorId ||
        creator.minecraftPlayerUuid != effectiveMinecraftPlayerUuid ||
        creator.creatorIdProvider != creatorIdProvider;

      if (!modified) {
        return creator;
      }

      // Update the Creator Name and Hardware IDs, and Creator ID if it was reset.
      const updatedCreator = await this.prisma.creator.update({
        where: { id: creator.id },
        data: {
          creatorName:
            // Validate the Creator Name if it changed.
            creator.creatorName == effectiveCreatorName
              ? effectiveCreatorName
              : CreatorService.validateCreatorName(effectiveCreatorName),
          creatorNameSlug,
          allowCreatorIdReset: false,
          creatorId: effectiveCreatorId,
          creatorIdProvider,
          minecraftPlayerUuid: effectiveMinecraftPlayerUuid,
          hwids: Array.from(new Set([hwid, ...creator.hwids])).slice(0, 3),
          ips: Array.from(new Set([ip, ...creator.ips])).slice(0, 3)
        }
      });

      if (updatedCreator.creatorName != creator.creatorName) {
        backgroundUpdateCreatorNameTranslation.call(this, updatedCreator);
      }

      this.logger.verbose(`Updated creator "${creator.creatorName}".`);

      return updatedCreator;
    }

    function backgroundUpdateCreatorNameTranslation(
      this: CreatorService,
      creatorToTranslate: Creator
    ): void {
      this.updateCreatorNameTranslation(creatorToTranslate).catch(error => {
        this.logger.error(
          `Failed to translate creator name "${creatorToTranslate.creatorName}" (#${creatorToTranslate.id}).`,
          error
        );

        sentry.captureException(error);
      });
    }
  }

  /**
   * Transforms a Creator Name to a slug-style one used to check for username collisions or future
   * URL routing.
   */
  public getCreatorNameSlug(name: string | null): string | null {
    if (!name?.trim()) {
      return null;
    }

    return (
      name
        .replaceAll("'", '')
        .replaceAll('’', '')
        // Replace consecutive spaces or hyphens with a single hyphen.
        .replace(/\s+|-+/g, '-')
        // Remove leading and trailing hyphens.
        .replace(/^-+|-+$/g, '')
        .toLowerCase()
    );
  }

  /**
   * Update of the transliteration and translation of the creator name for the given screenshot,
   * ignoring {@link Creator.needsTranslation}.
   * Skips creators with names that are not eligible to transliteration/translation (see
   * {@link AiTranslatorService.isEligibleForTranslation}).
   */
  public async updateCreatorNameTranslation(
    creator: Pick<Creator, 'id' | 'creatorName'>
  ): Promise<{ translated: false } | { translated: true; creator: Creator }> {
    // If no translation is needed, mark the creator as not needing translation.
    if (
      !(creator.creatorName && AiTranslatorService.isEligibleForTranslation(creator.creatorName))
    ) {
      await this.prisma.creator.update({
        where: { id: creator.id },
        data: {
          needsTranslation: false,
          creatorNameLocale: null,
          creatorNameLatinized: null,
          creatorNameTranslated: null
        }
      });

      return { translated: false };
    }

    const result = await this.aiTranslator.translateCreatorName({
      creatorId: creator.id,
      input: creator.creatorName
    });

    // Update the screenshot with the new values.
    const updatedCreator = await this.prisma.creator.update({
      where: { id: creator.id },
      data: {
        needsTranslation: false,
        creatorNameLocale: result.twoLetterLocaleCode,
        creatorNameLatinized: result.transliteration,
        creatorNameTranslated: result.translation
      }
    });

    return { translated: true, creator: updatedCreator };
  }

  /**
   * Serializes a {@link Creator} to a JSON object for API responses.
   */
  public serialize(creator: Creator): JsonObject {
    return {
      id: creator.id,
      creatorName: creator.creatorName,
      creatorNameSlug: creator.creatorNameSlug,
      creatorNameLocale: creator.creatorNameLocale,
      creatorNameLatinized: creator.creatorNameLatinized,
      creatorNameTranslated: creator.creatorNameTranslated,
      createdAt: creator.createdAt.toISOString(),
      socials: creator.socials.map(social => ({
        platform: social.platform,
        link: `${config.http.baseUrl}/api/v1/creators/${creator.id}/social/${social.platform}`,
        clicks: social.clicks
      }))
    };
  }

  private ensureValidCreatorId(creatorId: string): void {
    if (!uuid.validate(creatorId) || uuid.version(creatorId) != 4) {
      throw new InvalidCreatorIdError(creatorId);
    }
  }

  /**
   * Trims start, end and consecutive spaces and validates that the string does not exceed 25
   * characters.
   *
   * @throws InvalidCreatorNameError If it is not a valid Creator Name.
   */
  private static validateCreatorName(name: string | null): string | null {
    if (!name?.trim()) {
      return null;
    }

    if (name.length > 25) {
      throw new InvalidCreatorNameError(name);
    }

    // Normalize multiple spaces to a single space.
    return name.replace(/\s+/g, ' ');
  }
}

export abstract class CreatorError extends StandardError {}

export class InvalidCreatorIdError extends CreatorError {
  public readonly creatorId: string;

  public constructor(creatorId: string) {
    super(`Invalid Creator ID "${creatorId}", an UUID v4 sequence was expected.`);

    this.creatorId = creatorId;
  }
}

export class MissingMinecraftOfficialAccessTokenError extends CreatorError {
  public constructor() {
    super(`Missing Minecraft official access token in Authorization payload.`);
  }
}

export class MissingMinecraftOfflinePlayerUuidError extends CreatorError {
  public constructor() {
    super(`Missing Minecraft offline player UUID in Authorization payload.`);
  }
}

export class InvalidMinecraftPlayerUuidError extends CreatorError {
  public readonly value: string;

  public constructor(value: string) {
    super(`Invalid Minecraft player UUID "${value}".`);

    this.value = value;
  }
}

export class UnsupportedCreatorIdProviderError extends CreatorError {
  public readonly provider: string;

  public constructor(provider: string) {
    super(`Unsupported creator ID provider "${provider}".`);

    this.provider = provider;
  }
}

export class MinecraftOfficialAuthenticationError extends CreatorError {
  public readonly cause: MinecraftAuthError;

  public constructor(cause: MinecraftAuthError) {
    super(cause.message);

    this.cause = cause;
  }
}

export class InvalidCreatorNameError extends CreatorError {
  public readonly incorrectName: string;

  public constructor(incorrectName: string) {
    super(`Creator Name "${incorrectName}" is invalid, it must between 1 and 25 characters long.`);

    this.incorrectName = incorrectName;
  }
}

export class CreatorNotFoundError extends CreatorError {
  public constructor() {
    super(`No Creator with this Creator ID was found.`);
  }
}

export class IncorrectCreatorIdError extends CreatorError {
  public override httpErrorType = ForbiddenException;

  public readonly creatorName: string;

  public constructor(creatorName: string) {
    super(
      oneLine`
      Incorrect Creator ID for user "${creatorName}".
      If you've never used HallOfFame before or just changed your Creator
      Name, this means this username is already claimed, choose another!
      Otherwise, check that you are logged in with the correct Paradox
      account.`
    );

    this.creatorName = creatorName;
  }
}
