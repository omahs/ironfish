/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
import { addBlock, NodeUtils } from '@ironfish/sdk'
import { IronfishCommand } from '../../command'
import { LocalFlags } from '../../flags'

export default class AddBlock extends IronfishCommand {
  static description = ''

  static args = [
    {
      name: 'path',
      parse: (input: string): Promise<string> => Promise.resolve(input.trim()),
      required: true,
    },
  ]

  static flags = {
    ...LocalFlags,
  }

  async start(): Promise<void> {
    const { args } = await this.parse(AddBlock)
    const path = args.path as string

    const node = await this.sdk.node()

    await NodeUtils.waitForOpen(node)

    await addBlock(node, path)
  }
}
